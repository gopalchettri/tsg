-- ============================================================================
-- TSG -- seed the ThreatLibrary from the functional team's ThreatLibrary.xlsx
-- (75 curated threats). Idempotent (guarded IF NOT EXISTS), safe to re-run.
--
-- Run order (all prerequisites, in sequence):
--   1. TSG_Core.sql -- creates Threat_Category/
--      Threat_Type/Threat_Catalogue/Threat_Actor/ThreatType_ThreatActor_Map.
--   2. Threat_library.sql -- creates the Config_Threat_Rule table
--      itself (TSG_Core.sql deliberately does not).
--   3. Threat_library.sql -- creates Threat_Catalogue_Category_Map
--      and the Threat_Type/Threat_Catalogue.Source columns this script writes to.
--   4. This script.
--
-- KNOWN GAP: 6 of 27 Threat Types mix IT and OT at the
-- individual-threat level (Config_Threat_Rule only scopes by ThreatTypeID, not
-- ThreatCatalogueID) -- no asset_type rule is emitted for these, to avoid wrongly
-- gating all their threats to one asset type: AI Abuse, Credential Abuse, Malware/Ransomware, Service Disruption, Social Engineering, Supply Chain Compromise
-- ============================================================================

-- Threat_Type/Threat_Catalogue/Threat_Actor all have filtered UNIQUE indexes
-- (UX_ThreatType_NaturalKey / UX_ThreatCatalogue_NaturalKey / UX_ThreatActor_NaturalKey,
-- TSG_Core.sql), and Threat_Type additionally has a filtered non-unique index
-- (IX_ThreatType_Category_Active). SQL Server requires QUOTED_IDENTIFIER ON for any
-- INSERT/UPDATE/DELETE against a table with a filtered index -- sqlcmd's own default is
-- OFF, and without this the very first Threat_Type insert below aborts the whole batch
-- (Msg 1934), confirmed by actually running this script. Same fix TSG_Core.sql
-- already applies at its own top for the same reason.
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;

-- 1. Threat_Category (STRIDE, 6) -- ThreatCategoryID is NOT IDENTITY (TSG_Core.sql),
-- every INSERT must supply it explicitly, same convention as Config_Threat_Rule below.
IF NOT EXISTS (SELECT 1 FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Category (ThreatCategoryID, ThreatCategoryName, IsActive, IsDeleted) VALUES (1, N'Denial of Service', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Category (ThreatCategoryID, ThreatCategoryName, IsActive, IsDeleted) VALUES (2, N'Elevation of Privilege', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Category (ThreatCategoryID, ThreatCategoryName, IsActive, IsDeleted) VALUES (3, N'Information Disclosure', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Category (ThreatCategoryID, ThreatCategoryName, IsActive, IsDeleted) VALUES (4, N'Repudiation', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Category (ThreatCategoryID, ThreatCategoryName, IsActive, IsDeleted) VALUES (5, N'Spoofing', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Threat_Category WHERE ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Category (ThreatCategoryID, ThreatCategoryName, IsActive, IsDeleted) VALUES (6, N'Tampering', 1, 0);

-- 2. Threat_Type (27)
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'AI Abuse', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Cloud/IIoT Abuse' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Cloud/IIoT Abuse', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Cloud/SaaS Abuse' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Cloud/SaaS Abuse', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Credential Abuse', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Data Theft/Tampering', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Data/Telemetry Abuse' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Data/Telemetry Abuse', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Detection Evasion' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Detection Evasion', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Engineering Access Abuse' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Engineering Access Abuse', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Engineering Workstation Compromise' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Engineering Workstation Compromise', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Field Asset Manipulation' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Field Asset Manipulation', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'HMI/SCADA Manipulation' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'HMI/SCADA Manipulation', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Logic/Configuration Manipulation' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Logic/Configuration Manipulation', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Malware/Ransomware', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Monitoring Evasion' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Monitoring Evasion', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'OT Network Intrusion' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'OT Network Intrusion', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'OT Service Exploitation' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'OT Service Exploitation', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Physical/Portable Media Compromise' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Physical/Portable Media Compromise', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Protocol/Command Abuse' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Protocol/Command Abuse', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Recovery Disruption' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Recovery Disruption', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Remote Access Abuse' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Remote Access Abuse', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Safety System Abuse' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Safety System Abuse', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Service Disruption', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Social Engineering', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Supply Chain Compromise', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Trust/Crypto Abuse' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Trust/Crypto Abuse', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Web/API Exploitation' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Web/API Exploitation', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Wireless/Comms Abuse' AND SectorID IS NULL)
    INSERT INTO Threat_Type (ThreatTypeName, SectorID, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Wireless/Comms Abuse', NULL, (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');

-- 3. Threat_Catalogue (75) -- Description = Threat Scenario + Theme precondition note
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Credential phishing and MFA session theft' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse' AND SectorID IS NULL), N'Credential phishing and MFA session theft', N'An attacker uses adversary-in-the-middle phishing, QR phishing or a fake collaboration link to capture a user’s password and MFA session token. The attacker then uses the trusted session to access email, SSO or business portals, registers persistence such as forwarding rules or trusted devices, and attempts movement to higher-value applications. [Precondition/Theme: Asset has user/admin login]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Password spray and credential stuffing' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse' AND SectorID IS NULL), N'Password spray and credential stuffing', N'An attacker uses leaked credentials from previous breaches or infostealer logs to run low-volume password spraying or credential stuffing against SSO, VPN, VDI, email and public portals. The activity is distributed over time and source locations to avoid simple lockout and alerting thresholds. [Precondition/Theme: Asset has user/admin login]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'OAuth consent and refresh-token abuse' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/SaaS Abuse' AND SectorID IS NULL), N'OAuth consent and refresh-token abuse', N'An attacker obtains OAuth consent, refresh tokens or delegated API permissions through a malicious application, compromised endpoint or stolen browser token. The attacker continues to access mail, files, SaaS records or APIs even after the user changes the password, unless the token and consent are revoked. [Precondition/Theme: Asset uses SaaS]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse' AND SectorID IS NULL), N'Privileged account takeover or misuse', N'A privileged administrator, support user, database administrator or break-glass account is compromised or misused. The account is used to change permissions, disable controls, export records, alter configurations or approve actions outside the normal change and segregation-of-duties process. [Precondition/Theme: Asset has privileged/admin access]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse' AND SectorID IS NULL), N'Shared, stale or orphaned account misuse', N'Users share accounts, continue using stale accounts, or leave vendor and transferred-user access active after role changes or contract termination. Actions performed through these accounts cannot be reliably attributed and may be used to access, approve, change or extract information without clear ownership. [Precondition/Theme: Asset has user/admin login]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering' AND SectorID IS NULL), N'Helpdesk identity reset fraud', N'An attacker impersonates an employee, executive or vendor during a helpdesk interaction and requests password reset, MFA reset, device registration or access reactivation. The request may use personal information, urgency, deepfake audio or compromised internal messages to pass identity checks. [Precondition/Theme: Asset has user/admin login]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Deepfake-enabled executive or vendor fraud' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering' AND SectorID IS NULL), N'Deepfake-enabled executive or vendor fraud', N'An attacker uses deepfake voice/video, spoofed email or compromised chat accounts to impersonate an executive, service owner or supplier. The attacker pressures staff to release payments, approve access, share sensitive information or bypass normal verification steps due to urgency or authority. [Precondition/Theme: Asset supports business transactions/approvals]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware' AND SectorID IS NULL), N'Ransomware with data theft extortion', N'An attacker gains initial access through phishing, exposed remote access, stolen credentials or a vulnerable internet-facing system. The attacker escalates privileges, disables security tools, exfiltrates data, encrypts servers or workstations, and threatens public leakage to force payment or operational pressure. [Precondition/Theme: Asset uses endpoint/server infrastructure]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware' AND SectorID IS NULL), N'Wiper or destructive script attack', N'An attacker deploys wiper malware or destructive scripts to delete files, corrupt databases, overwrite virtual machines or damage system configurations. The activity may be timed with a geopolitical event, major public event or operational peak to maximize disruption and recovery pressure. [Precondition/Theme: Asset is critical for service availability]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Infostealer or remote access malware' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware' AND SectorID IS NULL), N'Infostealer or remote access malware', N'An attacker delivers infostealer malware, remote access malware or a malicious attachment/link to a user endpoint. Once executed, the malware steals browser tokens, passwords, files and device information, or provides remote control for further intrusion into internal and cloud services. [Precondition/Theme: Asset uses endpoint/server infrastructure]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise' AND SectorID IS NULL), N'Remote support and RMM tool abuse', N'An attacker uses an approved remote support or remote monitoring tool, or installs a similar tool that blends into normal IT operations. The tool is then used to maintain access, transfer files, run commands or move across systems under the appearance of legitimate support activity. [Precondition/Theme: Asset has vendor remote access]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise' AND SectorID IS NULL), N'Software supply chain or vendor update compromise', N'An attacker compromises a software vendor, managed service provider, update package, library, integration or support channel used by the entity. The trusted supplier path is then used to deliver malicious code, steal data or access systems that would otherwise be difficult to reach directly. [Precondition/Theme: Asset is vendor-hosted/managed]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise' AND SectorID IS NULL), N'CI/CD and source repository compromise', N'An attacker compromises source-code repositories, CI/CD pipelines, build runners or deployment credentials. Malicious code, secrets, dependency changes or deployment scripts are introduced into applications or infrastructure before production release. [Precondition/Theme: Asset uses DevOps/source code pipeline]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse' AND SectorID IS NULL), N'Secrets, API key or service credential theft', N'API keys, service credentials, certificates or database secrets are exposed through code repositories, scripts, shared folders, logs, tickets or developer workstations. The attacker uses these secrets to call APIs, access databases, impersonate services or move between environments. [Precondition/Theme: Asset has API/integration links]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Web/API Exploitation' AND SectorID IS NULL), N'Public-facing application or API exploitation', N'An attacker exploits an internet-facing application, API, portal or gateway using known vulnerabilities, weak authentication flow, exposed management interface or insecure business logic. The attack may result in unauthorized access, command execution, data extraction or service disruption. [Precondition/Theme: Asset is internet-facing]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Web/API Exploitation' AND SectorID IS NULL), N'Injection or script execution attack', N'An attacker submits crafted input through web forms, APIs, file uploads or integration messages to execute unauthorized commands, SQL, scripts or templates. The attack abuses insufficient validation, encoding or execution controls to alter data, access restricted records or run code. [Precondition/Theme: Asset is internet-facing]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Web/API Exploitation' AND SectorID IS NULL), N'Unauthorized API or record access', N'An attacker manipulates API parameters, object identifiers, filters or record references to access data belonging to another user, entity or business process. The attack abuses gaps in object-level authorization or excessive API responses rather than using malware. [Precondition/Theme: Asset has API/integration links]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Business workflow manipulation' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Web/API Exploitation' AND SectorID IS NULL), N'Business workflow manipulation', N'An attacker manipulates a business workflow such as approval routing, payment release, permit issuance, case closure or exception handling. The attack may abuse excessive privileges, weak segregation of duties, missing step validation or altered master data to complete unauthorized outcomes. [Precondition/Theme: Asset supports business transactions/approvals]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Authoritative data tampering' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering' AND SectorID IS NULL), N'Authoritative data tampering', N'An attacker changes authoritative records such as customer/entity data, permits, service status, master data, configuration records, financial values or operational reference data. The change may be performed directly through an application, database, API or privileged administrative function. [Precondition/Theme: Asset stores sensitive data]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Bulk data exfiltration' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering' AND SectorID IS NULL), N'Bulk data exfiltration', N'An attacker or insider exports large volumes of records through email, cloud sync, removable media, API queries, database dumps or unmanaged file-sharing channels. The exfiltration may occur gradually to avoid thresholds or through a compromised account with legitimate data access. [Precondition/Theme: Asset supports bulk data export/import]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Cloud storage or sharing-link exposure' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering' AND SectorID IS NULL), N'Cloud storage or sharing-link exposure', N'Sensitive files, datasets or backups are placed in cloud storage, collaboration sites or sharing links with excessive access such as public, anyone-with-link or external sharing. External parties may discover or receive the link and access information without formal authorization. [Precondition/Theme: Asset uses SaaS]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/SaaS Abuse' AND SectorID IS NULL), N'Cloud tenant privilege takeover', N'An attacker compromises cloud administrator access, automation roles, access keys or privileged service principals. The attacker changes cloud permissions, copies data, disables logging, deploys unauthorized resources, alters network exposure or disrupts workloads supporting critical services. [Precondition/Theme: Asset is cloud-hosted]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/SaaS Abuse' AND SectorID IS NULL), N'SaaS tenant takeover', N'An attacker compromises a SaaS tenant administrator, integration account or vendor-managed configuration. The attacker changes permissions, exports records, disables controls, creates hidden access or manipulates workflows inside a business-critical SaaS platform. [Precondition/Theme: Asset uses SaaS]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DDoS and resource exhaustion attack' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption' AND SectorID IS NULL), N'DDoS and resource exhaustion attack', N'An attacker floods public websites, portals, APIs, DNS or network links with volumetric, protocol or application-layer traffic. The attack may be used for extortion, protest, distraction during another intrusion or to disrupt public access to critical digital services. [Precondition/Theme: Asset is internet-facing]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption' AND SectorID IS NULL), N'Bot-driven scraping, fake accounts or workflow abuse', N'Automated bots abuse digital channels to scrape data, create fake accounts, submit spam, bypass queues, hoard appointments or repeatedly test credentials and workflows. The activity may not breach systems directly but can distort service availability and data quality. [Precondition/Theme: Asset is internet-facing]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption' AND SectorID IS NULL), N'DNS, domain or route hijacking', N'An attacker compromises domain registrar access, DNS records, routing arrangements or certificates used by official services. Users are redirected to attacker-controlled infrastructure, email delivery is intercepted, or legitimate services become unreachable. [Precondition/Theme: Asset is internet-facing]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering' AND SectorID IS NULL), N'Man-in-the-middle or certificate abuse', N'An attacker intercepts network traffic through rogue Wi-Fi, proxy manipulation, certificate misuse, weak TLS configuration or compromised network path. The attacker captures credentials, modifies traffic or reads sensitive information moving between users, applications and third parties. [Precondition/Theme: Asset has API/integration links]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official messaging channel compromise' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering' AND SectorID IS NULL), N'Official messaging channel compromise', N'An attacker compromises official messaging channels such as SMS gateway, email distribution platform, chatbot, notification service or mass communication tool. The channel is used to send fraudulent instructions, malicious links, misleading service updates or unauthorized notices. [Precondition/Theme: Asset sends email/SMS/notifications]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Mobile, QR or collaboration-channel compromise' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering' AND SectorID IS NULL), N'Mobile, QR or collaboration-channel compromise', N'A user is targeted through mobile malware, malicious QR codes, fake support messages or compromised collaboration links. The attack steals credentials, tokens, files or approval codes from mobile and collaboration channels used to access business services. [Precondition/Theme: Asset sends email/SMS/notifications]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'Security log deletion or tampering' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Detection Evasion' AND SectorID IS NULL), N'Security log deletion or tampering', N'After gaining access, an attacker deletes, alters or suppresses security logs, audit records, alerts or system events. The attacker may change retention settings, disable connectors, clear local logs or modify timestamps to hide activity and delay investigation. [Precondition/Theme: Asset has privileged/admin access]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Detection Evasion' AND SectorID IS NULL), N'SIEM or alert pipeline overload', N'An attacker overwhelms monitoring by generating noisy events, disabling connectors, exploiting log ingestion limits, or targeting SIEM/SOC dependencies. High-value alerts may be hidden within noise or not delivered for investigation. [Precondition/Theme: Asset is critical for service availability]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption' AND SectorID IS NULL), N'Backup destruction or recovery sabotage', N'An attacker searches for backup consoles, backup repositories, snapshots and privileged backup credentials before launching disruptive activity. Backups are deleted, encrypted, expired, altered or made unrecoverable so the entity cannot restore services within the expected recovery window. [Precondition/Theme: Asset depends on backup/recovery]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise' AND SectorID IS NULL), N'Vendor-hosted platform cyber disruption', N'A cyber incident affects a vendor-hosted platform, managed service, SaaS provider, telecom provider or technology supplier that supports the entity’s service delivery. The entity may lose access, receive corrupted data, face delayed transactions or have limited visibility into the incident. [Precondition/Theme: Asset is vendor-hosted/managed]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Shadow SaaS or personal GenAI data leakage' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering' AND SectorID IS NULL), N'Shadow SaaS or personal GenAI data leakage', N'Staff upload sensitive records, documents, code or operational information into unmanaged SaaS, personal cloud tools or public GenAI services for convenience or productivity. The data may be retained, indexed, shared externally or used outside approved security and contractual controls. [Precondition/Theme: Asset uses SaaS]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse' AND SectorID IS NULL), N'Prompt injection against AI assistant', N'An attacker crafts prompts, uploaded content or retrieved documents that instruct an AI assistant to ignore system rules, reveal hidden information, perform unauthorized actions or call connected tools in an unintended way. The attack may be indirect through documents or web content processed by the model. [Precondition/Theme: Asset uses AI/chatbot/LLM]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse' AND SectorID IS NULL), N'LLM sensitive disclosure or agent overreach', N'An AI assistant or agent is given access to sensitive data, tools or workflow actions without sufficient boundaries. A user prompt, compromised context or design weakness causes it to expose restricted information, take actions beyond approval, or combine data across contexts inappropriately. [Precondition/Theme: Asset uses AI/chatbot/LLM]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse' AND SectorID IS NULL), N'AI training or retrieval data poisoning', N'An attacker manipulates training data, retrieval content, knowledge bases, embeddings or feedback used by AI systems. The poisoned content influences outputs, hides malicious guidance, misclassifies events or causes the AI system to make unsafe or incorrect recommendations. [Precondition/Theme: Asset uses AI/chatbot/LLM]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Encrypted data harvesting or cryptographic downgrade' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering' AND SectorID IS NULL), N'Encrypted data harvesting or cryptographic downgrade', N'An attacker captures encrypted traffic or stored encrypted data for later decryption, or forces weaker cryptographic settings through downgrade, weak certificate or legacy protocol abuse. The attack targets long-lived sensitive information that may remain valuable in the future. [Precondition/Theme: Asset stores sensitive data]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse' AND SectorID IS NULL), N'Lost device or stolen session exposure', N'A laptop, mobile device, removable media or active browser session is lost, stolen or accessed by an unauthorized person. If device encryption, session controls or remote wipe are weak, cached credentials, files and tokens may be used to access business systems. [Precondition/Theme: Asset uses endpoint/server infrastructure]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering' AND SectorID IS NULL), N'Official social media or content publishing takeover', N'An attacker compromises official social media, public website content management or publishing accounts. The attacker posts false information, malicious links, service disruption messages or reputationally damaging content during normal operations or a public event. [Precondition/Theme: Asset is internet-facing]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'OT remote credential theft and session takeover' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse' AND SectorID IS NULL), N'OT remote credential theft and session takeover', N'Threat actors phish, steal or reuse OT user, VPN, VDI, engineering or support credentials and use the valid login to enter the OT environment. The access is then used to view operational screens, collect engineering information, stage tools or move towards privileged systems without appearing as an unknown user. [Precondition/Theme: Asset has OT user/admin login]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse' AND SectorID IS NULL), N'Shared, default or stale OT account abuse', N'Threat actors use shared operator accounts, default vendor accounts, orphaned users or stale maintenance credentials that remain active in OT systems. The accounts allow actions to be performed under a generic or unmanaged identity and make it difficult to prove who changed, viewed or executed an operational action. [Precondition/Theme: Asset has OT user/admin login]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Access Abuse' AND SectorID IS NULL), N'Privileged engineering account misuse', N'A privileged operator, engineer, database administrator, domain administrator or support account is compromised or misused to change configurations, bypass approval steps, modify files, disable safeguards or execute commands beyond normal operational need. [Precondition/Theme: Asset has privileged/engineering access]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Remote Access Abuse' AND SectorID IS NULL), N'Vendor remote access compromise', N'Threat actors compromise a vendor, system integrator or remote support account and use approved maintenance channels to access OT assets. The activity may occur through VPN, remote support tools, jump hosts or undocumented connectivity retained after a project or contract ends. [Precondition/Theme: Asset has vendor/remote access]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Jump server or emergency access bypass' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Remote Access Abuse' AND SectorID IS NULL), N'Jump server or emergency access bypass', N'Threat actors bypass the intended OT jump server, bastion host, PAM workflow or emergency access process by using alternate routes, unmanaged VPN paths, dual-homed systems or direct connections to OT hosts. This avoids session recording, approval controls and command monitoring. [Precondition/Theme: Asset uses jump server or OT remote access]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Network Intrusion' AND SectorID IS NULL), N'IT-to-OT lateral movement', N'Threat actors first compromise IT identity, Active Directory, endpoint, file transfer, DMZ or shared infrastructure and then move laterally towards OT networks through weak segmentation, excessive trust, dual-homed hosts or allowed cross-zone services. [Precondition/Theme: Asset connects IT and OT networks]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Service Exploitation' AND SectorID IS NULL), N'Internet-exposed OT service exploitation', N'Threat actors discover exposed HMIs, PLC interfaces, remote access portals, engineering services or management interfaces through scanning and exploit them to gain unauthorized visibility or access to OT functions. [Precondition/Theme: Asset is internet-reachable or exposed through OT DMZ]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Workstation Compromise' AND SectorID IS NULL), N'Engineering workstation compromise', N'Threat actors compromise an engineering workstation, programming laptop or project repository through phishing, malware, portable media, stolen laptop or weak endpoint controls. The workstation is then used to access controller projects, firmware files, recipes, network paths or privileged tools. [Precondition/Theme: Asset includes engineering workstation/tools]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Logic/Configuration Manipulation' AND SectorID IS NULL), N'Unauthorized controller logic change', N'Threat actors use engineering tools or compromised engineering access to upload, download or modify PLC, RTU, IED or controller logic. The change may alter operating sequences, create a hidden trigger, bypass validation or prepare future disruption. [Precondition/Theme: Asset includes PLC/RTU/IED/controller logic]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Controller mode, I/O or drive manipulation' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Logic/Configuration Manipulation' AND SectorID IS NULL), N'Controller mode, I/O or drive manipulation', N'Threat actors manipulate controller run/stop mode, force I/O points, change VFD or motor drive parameters, adjust control loop tuning or modify calibration values. The actions can be performed through engineering tools, HMI functions or direct controller access. [Precondition/Theme: Asset includes PLC/RTU/IED/controller logic]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'HMI/SCADA Manipulation' AND SectorID IS NULL), N'HMI/SCADA setpoint and command manipulation', N'Threat actors use compromised HMI, SCADA or operator access to issue unauthorized commands, change setpoints, alter batch/recipe parameters or spoof operator instructions. The attack relies on the system accepting the action as a legitimate operator command. [Precondition/Theme: Asset has HMI/SCADA operator interface]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'HMI/SCADA Manipulation' AND SectorID IS NULL), N'Alarm and operator view suppression', N'Threat actors manipulate HMI displays, alarm thresholds, event lists or SCADA screens to hide the true process state from operators. The attacker may suppress alarms, replay normal values or change visual indicators while the underlying process is abnormal. [Precondition/Theme: Asset has HMI/SCADA operator interface]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Protocol/Command Abuse' AND SectorID IS NULL), N'OT protocol command abuse', N'Threat actors abuse insecure or weakly controlled OT protocols such as Modbus/TCP, DNP3, IEC 61850, IEC 60870-5-104, EtherNet/IP, CIP, PROFINET or OPC to send unauthorized commands, intercept traffic or manipulate device communication. [Precondition/Theme: Asset uses OT protocols]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND tc.ThreatName = N'Wireless, radio or satellite link abuse' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Wireless/Comms Abuse' AND SectorID IS NULL), N'Wireless, radio or satellite link abuse', N'Threat actors spoof, jam, intercept or compromise wireless industrial networks, radio telemetry, cellular routers or satellite communication links used by remote OT sites. The attacker may disrupt connectivity or inject misleading telemetry. [Precondition/Theme: Asset uses wireless/radio/satellite communication]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'OT data and telemetry tampering' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data/Telemetry Abuse' AND SectorID IS NULL), N'OT data and telemetry tampering', N'Threat actors alter process values, sensor readings, point mappings, calibration data, historian records or gateway telemetry so that operators, analytics tools and reporting systems receive incorrect operational information. [Precondition/Theme: Asset stores historian or operational data]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'Historian and OT documentation exfiltration' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data/Telemetry Abuse' AND SectorID IS NULL), N'Historian and OT documentation exfiltration', N'Threat actors extract historian data, engineering drawings, controller projects, network diagrams, remote site documentation or operational procedures from OT repositories, collaboration tools or data transfer paths. [Precondition/Theme: Asset stores historian or operational data]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware' AND SectorID IS NULL), N'Ransomware on OT support systems', N'Ransomware reaches OT-connected Windows hosts, HMIs, SCADA servers, historians, engineering workstations, virtualization platforms or backup repositories and encrypts or disables systems required for visibility and operations. [Precondition/Theme: Asset uses OT Windows/server infrastructure]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Destructive wiper or worm propagation' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware' AND SectorID IS NULL), N'Destructive wiper or worm propagation', N'Threat actors deploy wiper malware or worm-like malware across OT Windows systems and shared services to destroy files, damage operating environments, disrupt recovery or spread rapidly through trusted OT paths. [Precondition/Theme: Asset uses OT Windows/server infrastructure]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware' AND SectorID IS NULL), N'ICS-specific malware or firmware implant', N'Threat actors deploy ICS-specific malware, malicious firmware, controller implants or device-specific payloads designed to interact with PLCs, field devices or industrial protocols rather than only encrypting IT systems. [Precondition/Theme: Asset includes PLC/RTU/IED/controller logic]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Physical/Portable Media Compromise' AND SectorID IS NULL), N'Removable media or portable device compromise', N'Threat actors introduce malware, stolen credentials or modified project files through USB drives, engineering adapters, portable media, mobile devices or lost engineering laptops that are later connected to OT systems. [Precondition/Theme: Asset uses removable media or engineering laptops]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Physical/Portable Media Compromise' AND SectorID IS NULL), N'Rogue device or physical port abuse', N'Threat actors gain physical or near-site access to field cabinets, OT switch ports, serial interfaces, remote terminal sites or device panels and connect rogue equipment, cycle devices, tamper with hardware or create an unauthorized network path. [Precondition/Theme: Asset has physical field equipment/cabinets]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise' AND SectorID IS NULL), N'Compromised OT supply chain or hardware', N'Threat actors compromise ICS software packages, vendor websites, update channels, engineering tools, firmware images, replacement hardware or third-party components before they are installed or used in the OT environment. [Precondition/Theme: Asset is vendor-maintained or uses third-party components]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Service Exploitation' AND SectorID IS NULL), N'Legacy OT service exploitation', N'Threat actors exploit unsupported operating systems, unpatched OT hosts, legacy services, outdated protocol stacks or known exploitable vulnerabilities where downtime constraints delay remediation. [Precondition/Theme: Asset includes legacy or unsupported OT components]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Unsafe maintenance, scanning or patch disruption' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption' AND SectorID IS NULL), N'Unsafe maintenance, scanning or patch disruption', N'A user, vendor or attacker runs active scanning, applies an incompatible patch, changes firewall rules or performs maintenance without OT validation and rollback planning. The activity disrupts fragile devices, communication paths or application services. [Precondition/Theme: Asset undergoes OT maintenance, scanning or patching]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Trust/Crypto Abuse' AND SectorID IS NULL), N'Cryptographic trust, certificate or key abuse', N'Threat actors or negligent administrators exploit expired certificates, weak trust configuration, exposed private keys or obsolete cryptography to impersonate trusted endpoints, interrupt encrypted communication or weaken OT authentication. [Precondition/Theme: Asset has certificates/keys/time/DNS dependencies]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption' AND SectorID IS NULL), N'Time, DNS and infrastructure service manipulation', N'Threat actors manipulate or disrupt time synchronization, DNS, DHCP, name resolution or supporting infrastructure services used by OT systems and connected applications. [Precondition/Theme: Asset has certificates/keys/time/DNS dependencies]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Recovery Disruption' AND SectorID IS NULL), N'Backup and recovery compromise', N'Threat actors delete, encrypt, corrupt or access OT backups, controller project files, gold images, engineering repositories, recovery vaults or restore procedures before or during an incident. [Precondition/Theme: Asset depends on backup/restore/recovery]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Loss of manual fallback or incident containment' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption' AND SectorID IS NULL), N'Loss of manual fallback or incident containment', N'Threat actors disrupt automation, visibility or control while the entity lacks tested manual fallback, cyber playbooks, isolation procedures or cross-functional response steps. The incident spreads or persists because operators cannot safely contain the cyber-induced operational loss. [Precondition/Theme: Asset is critical for process availability]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'OT communications or access-layer denial of service' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption' AND SectorID IS NULL), N'OT communications or access-layer denial of service', N'Threat actors flood, jam, resource-exhaust or otherwise disrupt OT remote access portals, DMZ services, SCADA communication links, controller resources, network paths or critical communication services. [Precondition/Theme: Asset is critical for process availability]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND tc.ThreatName = N'OT monitoring and logging evasion' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Monitoring Evasion' AND SectorID IS NULL), N'OT monitoring and logging evasion', N'Threat actors disable, tamper with or route around OT logs, SIEM/SOC feeds, Level 1/2 monitoring sensors, event collectors or detection rules to remain undetected while reconnaissance, access or manipulation continues. [Precondition/Theme: Asset requires OT monitoring/logging]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Safety System Abuse' AND SectorID IS NULL), N'Safety system manipulation', N'Threat actors target safety instrumented systems, interlocks, emergency shutdown logic or safety controllers to disable protective functions, alter safety logic or create a mismatch between process risk and automated protection. [Precondition/Theme: Asset has safety system or interlocks]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/IIoT Abuse' AND SectorID IS NULL), N'Cloud, IIoT or edge gateway compromise', N'Threat actors compromise cloud-connected OT services, edge gateways, IIoT sensors, cellular routers, remote monitoring platforms or cloud admin consoles that interact with OT data or field assets. [Precondition/Theme: Asset uses IIoT/edge/cloud integration]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Field Asset Manipulation' AND SectorID IS NULL), N'Sector-specific connected field asset manipulation', N'Threat actors target connected DER, BESS, AMI, EV charging, district cooling, desalination, hydropower or similar sector-specific field assets through remote commands, gateways, head-end platforms or local controllers. [Precondition/Theme: Asset is sector-specific field asset]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering' AND SectorID IS NULL), N'OT personnel social engineering', N'Threat actors deceive control-room operators, engineers, vendors or support staff through phishing, urgent phone calls, fake maintenance requests, deepfake audio/video or compromised collaboration accounts to obtain access, approvals or unsafe operational actions. [Precondition/Theme: Asset has OT operators, engineers or vendor users]', NULL, 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation' AND tc.SectorID IS NULL)
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, Description, SectorID, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse' AND SectorID IS NULL), N'AI-assisted OT decision or data manipulation', N'Threat actors manipulate AI prompts, OT data pipelines, model inputs, AI assistant outputs or analytics recommendations used by operators, SOC teams or engineers. The attacker uses the AI workflow to hide signals, reveal sensitive OT data or influence operational decisions. [Precondition/Theme: Asset uses AI/analytics for OT decisions]', NULL, 1, 0, N'functional_team_excel');

-- 4. Threat_Catalogue_Category_Map (per-threat STRIDE links)
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Credential phishing and MFA session theft' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Credential phishing and MFA session theft' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Credential phishing and MFA session theft' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Credential phishing and MFA session theft' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Credential phishing and MFA session theft' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Credential phishing and MFA session theft' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Password spray and credential stuffing' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Password spray and credential stuffing' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Password spray and credential stuffing' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Password spray and credential stuffing' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Password spray and credential stuffing' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Password spray and credential stuffing' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'OAuth consent and refresh-token abuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'OAuth consent and refresh-token abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'OAuth consent and refresh-token abuse' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'OAuth consent and refresh-token abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'OAuth consent and refresh-token abuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'OAuth consent and refresh-token abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'OAuth consent and refresh-token abuse' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'OAuth consent and refresh-token abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Deepfake-enabled executive or vendor fraud' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Deepfake-enabled executive or vendor fraud' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Deepfake-enabled executive or vendor fraud' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Deepfake-enabled executive or vendor fraud' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Deepfake-enabled executive or vendor fraud' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Deepfake-enabled executive or vendor fraud' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Deepfake-enabled executive or vendor fraud' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Deepfake-enabled executive or vendor fraud' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Infostealer or remote access malware' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Infostealer or remote access malware' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Infostealer or remote access malware' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Infostealer or remote access malware' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Infostealer or remote access malware' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Infostealer or remote access malware' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Infostealer or remote access malware' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Infostealer or remote access malware' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Business workflow manipulation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Business workflow manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Business workflow manipulation' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Business workflow manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Business workflow manipulation' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Business workflow manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Business workflow manipulation' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Business workflow manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Authoritative data tampering' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Authoritative data tampering' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Authoritative data tampering' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Authoritative data tampering' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Authoritative data tampering' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Authoritative data tampering' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Authoritative data tampering' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Authoritative data tampering' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Bulk data exfiltration' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Bulk data exfiltration' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Bulk data exfiltration' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Bulk data exfiltration' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Bulk data exfiltration' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Bulk data exfiltration' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Cloud storage or sharing-link exposure' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Cloud storage or sharing-link exposure' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Cloud storage or sharing-link exposure' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Cloud storage or sharing-link exposure' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DDoS and resource exhaustion attack' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DDoS and resource exhaustion attack' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official messaging channel compromise' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official messaging channel compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official messaging channel compromise' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official messaging channel compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official messaging channel compromise' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official messaging channel compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official messaging channel compromise' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official messaging channel compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Mobile, QR or collaboration-channel compromise' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Mobile, QR or collaboration-channel compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Mobile, QR or collaboration-channel compromise' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Mobile, QR or collaboration-channel compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Mobile, QR or collaboration-channel compromise' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Mobile, QR or collaboration-channel compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Mobile, QR or collaboration-channel compromise' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Mobile, QR or collaboration-channel compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'Security log deletion or tampering' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'Security log deletion or tampering' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'Security log deletion or tampering' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'Security log deletion or tampering' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'Security log deletion or tampering' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'Security log deletion or tampering' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'Security log deletion or tampering' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'Security log deletion or tampering' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Shadow SaaS or personal GenAI data leakage' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Shadow SaaS or personal GenAI data leakage' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Shadow SaaS or personal GenAI data leakage' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Shadow SaaS or personal GenAI data leakage' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Encrypted data harvesting or cryptographic downgrade' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Encrypted data harvesting or cryptographic downgrade' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Encrypted data harvesting or cryptographic downgrade' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Encrypted data harvesting or cryptographic downgrade' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Encrypted data harvesting or cryptographic downgrade' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Encrypted data harvesting or cryptographic downgrade' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Encrypted data harvesting or cryptographic downgrade' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Encrypted data harvesting or cryptographic downgrade' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'OT remote credential theft and session takeover' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'OT remote credential theft and session takeover' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'OT remote credential theft and session takeover' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'OT remote credential theft and session takeover' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'OT remote credential theft and session takeover' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'OT remote credential theft and session takeover' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'OT remote credential theft and session takeover' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'OT remote credential theft and session takeover' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Jump server or emergency access bypass' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Jump server or emergency access bypass' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Jump server or emergency access bypass' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Jump server or emergency access bypass' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Jump server or emergency access bypass' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Jump server or emergency access bypass' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Jump server or emergency access bypass' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Jump server or emergency access bypass' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Controller mode, I/O or drive manipulation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Controller mode, I/O or drive manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Controller mode, I/O or drive manipulation' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Controller mode, I/O or drive manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Controller mode, I/O or drive manipulation' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Controller mode, I/O or drive manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Controller mode, I/O or drive manipulation' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Controller mode, I/O or drive manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND tc.ThreatName = N'Wireless, radio or satellite link abuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND tc.ThreatName = N'Wireless, radio or satellite link abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND tc.ThreatName = N'Wireless, radio or satellite link abuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND tc.ThreatName = N'Wireless, radio or satellite link abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND tc.ThreatName = N'Wireless, radio or satellite link abuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND tc.ThreatName = N'Wireless, radio or satellite link abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND tc.ThreatName = N'Wireless, radio or satellite link abuse' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND tc.ThreatName = N'Wireless, radio or satellite link abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'OT data and telemetry tampering' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'OT data and telemetry tampering' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'OT data and telemetry tampering' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'OT data and telemetry tampering' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'OT data and telemetry tampering' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'OT data and telemetry tampering' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'OT data and telemetry tampering' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'OT data and telemetry tampering' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'Historian and OT documentation exfiltration' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'Historian and OT documentation exfiltration' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'Historian and OT documentation exfiltration' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'Historian and OT documentation exfiltration' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'Historian and OT documentation exfiltration' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'Historian and OT documentation exfiltration' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Destructive wiper or worm propagation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Destructive wiper or worm propagation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Destructive wiper or worm propagation' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Destructive wiper or worm propagation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Destructive wiper or worm propagation' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Destructive wiper or worm propagation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Destructive wiper or worm propagation' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Destructive wiper or worm propagation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Unsafe maintenance, scanning or patch disruption' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Unsafe maintenance, scanning or patch disruption' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Unsafe maintenance, scanning or patch disruption' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Unsafe maintenance, scanning or patch disruption' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Unsafe maintenance, scanning or patch disruption' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Unsafe maintenance, scanning or patch disruption' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Loss of manual fallback or incident containment' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Loss of manual fallback or incident containment' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Loss of manual fallback or incident containment' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Loss of manual fallback or incident containment' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Loss of manual fallback or incident containment' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Loss of manual fallback or incident containment' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'OT communications or access-layer denial of service' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'OT communications or access-layer denial of service' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'OT communications or access-layer denial of service' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'OT communications or access-layer denial of service' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND tc.ThreatName = N'OT monitoring and logging evasion' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND tc.ThreatName = N'OT monitoring and logging evasion' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND tc.ThreatName = N'OT monitoring and logging evasion' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND tc.ThreatName = N'OT monitoring and logging evasion' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND tc.ThreatName = N'OT monitoring and logging evasion' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND tc.ThreatName = N'OT monitoring and logging evasion' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND tc.ThreatName = N'OT monitoring and logging evasion' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND tc.ThreatName = N'OT monitoring and logging evasion' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation' AND tc.SectorID IS NULL),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));

-- 5. Threat_Actor (13)
IF NOT EXISTS (SELECT 1 FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal')
    INSERT INTO Threat_Actor (ThreatActorName, IsCapable, IsActive, IsDeleted) VALUES (N'Cybercriminal', 1, 1, 0);
IF NOT EXISTS (SELECT 1 FROM Threat_Actor WHERE ThreatActorName = N'External attacker')
    INSERT INTO Threat_Actor (ThreatActorName, IsCapable, IsActive, IsDeleted) VALUES (N'External attacker', 1, 1, 0);
IF NOT EXISTS (SELECT 1 FROM Threat_Actor WHERE ThreatActorName = N'Hacktivist')
    INSERT INTO Threat_Actor (ThreatActorName, IsCapable, IsActive, IsDeleted) VALUES (N'Hacktivist', 1, 1, 0);
IF NOT EXISTS (SELECT 1 FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider')
    INSERT INTO Threat_Actor (ThreatActorName, IsCapable, IsActive, IsDeleted) VALUES (N'Malicious insider', 1, 1, 0);
IF NOT EXISTS (SELECT 1 FROM Threat_Actor WHERE ThreatActorName = N'Malicious user')
    INSERT INTO Threat_Actor (ThreatActorName, IsCapable, IsActive, IsDeleted) VALUES (N'Malicious user', 1, 1, 0);
IF NOT EXISTS (SELECT 1 FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT')
    INSERT INTO Threat_Actor (ThreatActorName, IsCapable, IsActive, IsDeleted) VALUES (N'Nation-state/APT', 1, 1, 0);
IF NOT EXISTS (SELECT 1 FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider')
    INSERT INTO Threat_Actor (ThreatActorName, IsCapable, IsActive, IsDeleted) VALUES (N'Negligent insider', 1, 1, 0);
IF NOT EXISTS (SELECT 1 FROM Threat_Actor WHERE ThreatActorName = N'Ransomware affiliate')
    INSERT INTO Threat_Actor (ThreatActorName, IsCapable, IsActive, IsDeleted) VALUES (N'Ransomware affiliate', 1, 1, 0);
IF NOT EXISTS (SELECT 1 FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor')
    INSERT INTO Threat_Actor (ThreatActorName, IsCapable, IsActive, IsDeleted) VALUES (N'Third-party/Vendor', 1, 1, 0);
IF NOT EXISTS (SELECT 1 FROM Threat_Actor WHERE ThreatActorName = N'Terrorist/Extremist')
    INSERT INTO Threat_Actor (ThreatActorName, IsCapable, IsActive, IsDeleted) VALUES (N'Terrorist/Extremist', 1, 1, 0);
IF NOT EXISTS (SELECT 1 FROM Threat_Actor WHERE ThreatActorName = N'Industrial Spy/Competitor')
    INSERT INTO Threat_Actor (ThreatActorName, IsCapable, IsActive, IsDeleted) VALUES (N'Industrial Spy/Competitor', 1, 1, 0);
IF NOT EXISTS (SELECT 1 FROM Threat_Actor WHERE ThreatActorName = N'Supply Chain Attacker')
    INSERT INTO Threat_Actor (ThreatActorName, IsCapable, IsActive, IsDeleted) VALUES (N'Supply Chain Attacker', 1, 1, 0);
IF NOT EXISTS (SELECT 1 FROM Threat_Actor WHERE ThreatActorName = N'Physical Intruder/Saboteur')
    INSERT INTO Threat_Actor (ThreatActorName, IsCapable, IsActive, IsDeleted) VALUES (N'Physical Intruder/Saboteur', 1, 1, 0);

-- 6. ThreatType_ThreatActor_Map (deduped type/actor pairs)
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/SaaS Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/SaaS Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/SaaS Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Social Engineering' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Social Engineering' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Social Engineering' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Social Engineering' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Ransomware affiliate')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Ransomware affiliate'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Web/API Exploitation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Web/API Exploitation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Web/API Exploitation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Web/API Exploitation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Web/API Exploitation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/SaaS Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/SaaS Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Service Disruption' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Service Disruption' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Service Disruption' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Hacktivist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Hacktivist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Service Disruption' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Service Disruption' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Social Engineering' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Detection Evasion' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Detection Evasion' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Detection Evasion' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Detection Evasion' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Service Disruption' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Ransomware affiliate')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Ransomware affiliate'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Service Disruption' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Service Disruption' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'AI Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'AI Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'AI Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Malicious user')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious user'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'AI Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'AI Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'AI Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Social Engineering' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Hacktivist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Hacktivist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Access Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Access Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Access Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Access Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Remote Access Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Remote Access Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Remote Access Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Remote Access Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Remote Access Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Network Intrusion' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Network Intrusion' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Network Intrusion' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Service Exploitation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Hacktivist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Service Exploitation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Hacktivist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Service Exploitation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Service Exploitation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Workstation Compromise' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Workstation Compromise' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Workstation Compromise' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Workstation Compromise' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Logic/Configuration Manipulation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Logic/Configuration Manipulation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Logic/Configuration Manipulation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Logic/Configuration Manipulation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'HMI/SCADA Manipulation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'HMI/SCADA Manipulation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'HMI/SCADA Manipulation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'HMI/SCADA Manipulation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Protocol/Command Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Protocol/Command Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Protocol/Command Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Wireless/Comms Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Wireless/Comms Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Hacktivist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Wireless/Comms Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Hacktivist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data/Telemetry Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data/Telemetry Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data/Telemetry Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data/Telemetry Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Hacktivist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Hacktivist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Physical/Portable Media Compromise' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Physical/Portable Media Compromise' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Physical/Portable Media Compromise' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Physical/Portable Media Compromise' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Physical/Portable Media Compromise' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Trust/Crypto Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Trust/Crypto Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Trust/Crypto Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Recovery Disruption' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Recovery Disruption' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Recovery Disruption' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Monitoring Evasion' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Monitoring Evasion' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Monitoring Evasion' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Safety System Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Safety System Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/IIoT Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/IIoT Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/IIoT Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/IIoT Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Field Asset Manipulation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Field Asset Manipulation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Hacktivist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Field Asset Manipulation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Hacktivist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Field Asset Manipulation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Social Engineering' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'AI Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Service Disruption' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Terrorist/Extremist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Terrorist/Extremist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Terrorist/Extremist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Safety System Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Terrorist/Extremist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Terrorist/Extremist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'HMI/SCADA Manipulation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Terrorist/Extremist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Terrorist/Extremist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Field Asset Manipulation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Terrorist/Extremist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Terrorist/Extremist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Network Intrusion' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Terrorist/Extremist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Terrorist/Extremist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Recovery Disruption' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Terrorist/Extremist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Industrial Spy/Competitor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Industrial Spy/Competitor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Industrial Spy/Competitor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Access Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Industrial Spy/Competitor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Industrial Spy/Competitor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Workstation Compromise' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Industrial Spy/Competitor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Industrial Spy/Competitor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data/Telemetry Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Industrial Spy/Competitor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Industrial Spy/Competitor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Trust/Crypto Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Industrial Spy/Competitor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Supply Chain Attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Supply Chain Attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Supply Chain Attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Logic/Configuration Manipulation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Supply Chain Attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Supply Chain Attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Supply Chain Attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Supply Chain Attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Trust/Crypto Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Supply Chain Attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Physical Intruder/Saboteur')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Physical/Portable Media Compromise' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Physical Intruder/Saboteur'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Physical Intruder/Saboteur')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Safety System Abuse' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Physical Intruder/Saboteur'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Physical Intruder/Saboteur')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Field Asset Manipulation' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Physical Intruder/Saboteur'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tt.SectorID IS NULL AND ta.ThreatActorName = N'Physical Intruder/Saboteur')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Workstation Compromise' AND SectorID IS NULL),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Physical Intruder/Saboteur'));

-- 7. Config_Threat_Rule (asset_type gate) -- only for the 21 asset-type-PURE Threat Types
-- Skipped (mixed IT/OT, see header): AI Abuse, Credential Abuse, Malware/Ransomware, Service Disruption, Social Engineering, Supply Chain Compromise
-- ThreatRuleID is NOT IDENTITY (Threat_library.sql's own CREATE TABLE),
-- every INSERT must supply it explicitly. Threat_library.sql is a hard
-- prerequisite for this table's existence (nothing else creates it) but is now
-- schema-only (its own former 12-row legacy seed was removed -- see that script's
-- header for why), so this section is the table's only real seed data and can start
-- cleanly at 1.
IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule r JOIN Threat_Type tt ON r.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND r.RuleKey = N'asset_type')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted)
    VALUES (1, N'tech_gate', (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/IIoT Abuse' AND SectorID IS NULL), N'asset_type', N'Operational Technology (OT)', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule r JOIN Threat_Type tt ON r.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND r.RuleKey = N'asset_type')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted)
    VALUES (2, N'tech_gate', (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/SaaS Abuse' AND SectorID IS NULL), N'asset_type', N'Information Technology (IT)', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule r JOIN Threat_Type tt ON r.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND r.RuleKey = N'asset_type')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted)
    VALUES (3, N'tech_gate', (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering' AND SectorID IS NULL), N'asset_type', N'Information Technology (IT)', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule r JOIN Threat_Type tt ON r.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND r.RuleKey = N'asset_type')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted)
    VALUES (4, N'tech_gate', (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data/Telemetry Abuse' AND SectorID IS NULL), N'asset_type', N'Operational Technology (OT)', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule r JOIN Threat_Type tt ON r.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND r.RuleKey = N'asset_type')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted)
    VALUES (5, N'tech_gate', (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Detection Evasion' AND SectorID IS NULL), N'asset_type', N'Information Technology (IT)', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule r JOIN Threat_Type tt ON r.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND r.RuleKey = N'asset_type')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted)
    VALUES (6, N'tech_gate', (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Access Abuse' AND SectorID IS NULL), N'asset_type', N'Operational Technology (OT)', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule r JOIN Threat_Type tt ON r.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND r.RuleKey = N'asset_type')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted)
    VALUES (7, N'tech_gate', (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Workstation Compromise' AND SectorID IS NULL), N'asset_type', N'Operational Technology (OT)', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule r JOIN Threat_Type tt ON r.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND r.RuleKey = N'asset_type')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted)
    VALUES (8, N'tech_gate', (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Field Asset Manipulation' AND SectorID IS NULL), N'asset_type', N'Operational Technology (OT)', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule r JOIN Threat_Type tt ON r.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND r.RuleKey = N'asset_type')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted)
    VALUES (9, N'tech_gate', (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'HMI/SCADA Manipulation' AND SectorID IS NULL), N'asset_type', N'Operational Technology (OT)', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule r JOIN Threat_Type tt ON r.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND r.RuleKey = N'asset_type')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted)
    VALUES (10, N'tech_gate', (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Logic/Configuration Manipulation' AND SectorID IS NULL), N'asset_type', N'Operational Technology (OT)', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule r JOIN Threat_Type tt ON r.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND r.RuleKey = N'asset_type')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted)
    VALUES (11, N'tech_gate', (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Monitoring Evasion' AND SectorID IS NULL), N'asset_type', N'Operational Technology (OT)', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule r JOIN Threat_Type tt ON r.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND r.RuleKey = N'asset_type')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted)
    VALUES (12, N'tech_gate', (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Network Intrusion' AND SectorID IS NULL), N'asset_type', N'Operational Technology (OT)', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule r JOIN Threat_Type tt ON r.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND r.RuleKey = N'asset_type')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted)
    VALUES (13, N'tech_gate', (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Service Exploitation' AND SectorID IS NULL), N'asset_type', N'Operational Technology (OT)', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule r JOIN Threat_Type tt ON r.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND r.RuleKey = N'asset_type')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted)
    VALUES (14, N'tech_gate', (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Physical/Portable Media Compromise' AND SectorID IS NULL), N'asset_type', N'Operational Technology (OT)', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule r JOIN Threat_Type tt ON r.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND r.RuleKey = N'asset_type')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted)
    VALUES (15, N'tech_gate', (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Protocol/Command Abuse' AND SectorID IS NULL), N'asset_type', N'Operational Technology (OT)', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule r JOIN Threat_Type tt ON r.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND r.RuleKey = N'asset_type')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted)
    VALUES (16, N'tech_gate', (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Recovery Disruption' AND SectorID IS NULL), N'asset_type', N'Operational Technology (OT)', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule r JOIN Threat_Type tt ON r.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND r.RuleKey = N'asset_type')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted)
    VALUES (17, N'tech_gate', (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Remote Access Abuse' AND SectorID IS NULL), N'asset_type', N'Operational Technology (OT)', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule r JOIN Threat_Type tt ON r.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND r.RuleKey = N'asset_type')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted)
    VALUES (18, N'tech_gate', (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Safety System Abuse' AND SectorID IS NULL), N'asset_type', N'Operational Technology (OT)', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule r JOIN Threat_Type tt ON r.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND r.RuleKey = N'asset_type')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted)
    VALUES (19, N'tech_gate', (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Trust/Crypto Abuse' AND SectorID IS NULL), N'asset_type', N'Operational Technology (OT)', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule r JOIN Threat_Type tt ON r.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND r.RuleKey = N'asset_type')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted)
    VALUES (20, N'tech_gate', (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Web/API Exploitation' AND SectorID IS NULL), N'asset_type', N'Information Technology (IT)', 1, 0);
IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule r JOIN Threat_Type tt ON r.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND r.RuleKey = N'asset_type')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted)
    VALUES (21, N'tech_gate', (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Wireless/Comms Abuse' AND SectorID IS NULL), N'asset_type', N'Operational Technology (OT)', 1, 0);

-- Verify
SELECT (SELECT COUNT(*) FROM Threat_Category) AS categories, (SELECT COUNT(*) FROM Threat_Type WHERE Source = N'functional_team_excel') AS types,
       (SELECT COUNT(*) FROM Threat_Catalogue WHERE Source = N'functional_team_excel') AS catalogue_entries, (SELECT COUNT(*) FROM Threat_Actor) AS actors,
       (SELECT COUNT(*) FROM Threat_Catalogue_Category_Map) AS category_links, (SELECT COUNT(*) FROM ThreatType_ThreatActor_Map) AS actor_links,
       (SELECT COUNT(*) FROM Config_Threat_Rule WHERE RuleKey = N'asset_type') AS asset_type_rules;
