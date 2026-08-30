-- ============================================================================
-- Seed_to_Threat_library -- 75 curated threats, 346 category-map links and 140
-- type-actor links, from the functional team's ThreatLibrary.xlsx.
-- Idempotent (guarded IF NOT EXISTS), safe to re-run.
--
-- Run after 1. TSG_Core.sql and 2. Threat_library.sql, which create the master
-- tables and the Threat_Type/Threat_Catalogue.Source columns this fills.
--
-- KNOWN GAP: 6 of 27 Threat Types mix IT and OT at the individual-threat level.
-- Those six are DECLARED universal and validated per-asset by the Stage-1a LLM
-- validator: AI Abuse, Credential Abuse, Malware/Ransomware, Service Disruption,
-- Social Engineering, Supply Chain Compromise.
-- ============================================================================

-- The three master tables carry filtered indexes, and any INSERT against one
-- needs QUOTED_IDENTIFIER ON. sqlcmd defaults it OFF, and without this the first
-- Threat_Type insert below aborts the whole batch (Msg 1934).
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;

-- 1. Threat_Category (STRIDE, 6) -- ThreatCategoryID is NOT IDENTITY, so every
-- INSERT supplies it explicitly.
--
-- ThreatCategoryID ORDER IS NOT MEANINGFUL: the ids were assigned ALPHABETICALLY,
-- so ORDER BY ThreatCategoryID yields an order that looks canonical and is not.
-- app/core/stride.py owns the canonical sequence; every reference below resolves
-- a category BY NAME for the same reason.
--
-- ThreatCategoryCode carries the STRIDE letter so the order is legible in the
-- data. Written as idempotent UPDATEs so an already-seeded database picks them
-- up on the next run; the column is nullable and no code reads it.
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

-- STRIDE letters, matched by name so they land correctly whatever ids a database
-- holds. Documentation in the data; no code reads it.
UPDATE Threat_Category SET ThreatCategoryCode = N'S' WHERE ThreatCategoryName = N'Spoofing'               AND (ThreatCategoryCode IS NULL OR ThreatCategoryCode <> N'S');
UPDATE Threat_Category SET ThreatCategoryCode = N'T' WHERE ThreatCategoryName = N'Tampering'              AND (ThreatCategoryCode IS NULL OR ThreatCategoryCode <> N'T');
UPDATE Threat_Category SET ThreatCategoryCode = N'R' WHERE ThreatCategoryName = N'Repudiation'            AND (ThreatCategoryCode IS NULL OR ThreatCategoryCode <> N'R');
UPDATE Threat_Category SET ThreatCategoryCode = N'I' WHERE ThreatCategoryName = N'Information Disclosure' AND (ThreatCategoryCode IS NULL OR ThreatCategoryCode <> N'I');
UPDATE Threat_Category SET ThreatCategoryCode = N'D' WHERE ThreatCategoryName = N'Denial of Service'      AND (ThreatCategoryCode IS NULL OR ThreatCategoryCode <> N'D');
UPDATE Threat_Category SET ThreatCategoryCode = N'E' WHERE ThreatCategoryName = N'Elevation of Privilege' AND (ThreatCategoryCode IS NULL OR ThreatCategoryCode <> N'E');

-- 2. Threat_Type (27)
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'AI Abuse', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Cloud/IIoT Abuse')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Cloud/IIoT Abuse', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Cloud/SaaS Abuse')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Cloud/SaaS Abuse', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Credential Abuse', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Data Theft/Tampering', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Data/Telemetry Abuse')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Data/Telemetry Abuse', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Detection Evasion')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Detection Evasion', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Engineering Access Abuse')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Engineering Access Abuse', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Engineering Workstation Compromise')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Engineering Workstation Compromise', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Field Asset Manipulation')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Field Asset Manipulation', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'HMI/SCADA Manipulation')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'HMI/SCADA Manipulation', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Logic/Configuration Manipulation')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Logic/Configuration Manipulation', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Malware/Ransomware', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Monitoring Evasion')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Monitoring Evasion', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'OT Network Intrusion')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'OT Network Intrusion', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'OT Service Exploitation')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'OT Service Exploitation', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Physical/Portable Media Compromise')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Physical/Portable Media Compromise', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Protocol/Command Abuse')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Protocol/Command Abuse', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Recovery Disruption')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Recovery Disruption', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Remote Access Abuse')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Remote Access Abuse', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Safety System Abuse')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Safety System Abuse', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Service Disruption', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Social Engineering', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Supply Chain Compromise', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Trust/Crypto Abuse')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Trust/Crypto Abuse', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Web/API Exploitation')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Web/API Exploitation', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'), 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Type WHERE ThreatTypeName = N'Wireless/Comms Abuse')
    INSERT INTO Threat_Type (ThreatTypeName, ThreatCategoryID, IsActive, IsDeleted, Source)
    VALUES (N'Wireless/Comms Abuse', (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'), 1, 0, N'functional_team_excel');

-- 3. Threat_Catalogue (75) -- name only; Description removed 2026-08-30 (was the scenario prose)
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Credential phishing and MFA session theft')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse'), N'Credential phishing and MFA session theft', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Password spray and credential stuffing')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse'), N'Password spray and credential stuffing', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'OAuth consent and refresh-token abuse')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/SaaS Abuse'), N'OAuth consent and refresh-token abuse', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse'), N'Privileged account takeover or misuse', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse'), N'Shared, stale or orphaned account misuse', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering'), N'Helpdesk identity reset fraud', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Deepfake-enabled executive or vendor fraud')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering'), N'Deepfake-enabled executive or vendor fraud', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware'), N'Ransomware with data theft extortion', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware'), N'Wiper or destructive script attack', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Infostealer or remote access malware')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware'), N'Infostealer or remote access malware', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise'), N'Remote support and RMM tool abuse', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise'), N'Software supply chain or vendor update compromise', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise'), N'CI/CD and source repository compromise', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse'), N'Secrets, API key or service credential theft', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Web/API Exploitation'), N'Public-facing application or API exploitation', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Web/API Exploitation'), N'Injection or script execution attack', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Web/API Exploitation'), N'Unauthorized API or record access', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Business workflow manipulation')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Web/API Exploitation'), N'Business workflow manipulation', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Authoritative data tampering')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering'), N'Authoritative data tampering', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Bulk data exfiltration')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering'), N'Bulk data exfiltration', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Cloud storage or sharing-link exposure')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering'), N'Cloud storage or sharing-link exposure', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/SaaS Abuse'), N'Cloud tenant privilege takeover', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/SaaS Abuse'), N'SaaS tenant takeover', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DDoS and resource exhaustion attack')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption'), N'DDoS and resource exhaustion attack', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption'), N'Bot-driven scraping, fake accounts or workflow abuse', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption'), N'DNS, domain or route hijacking', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering'), N'Man-in-the-middle or certificate abuse', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official messaging channel compromise')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering'), N'Official messaging channel compromise', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Mobile, QR or collaboration-channel compromise')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering'), N'Mobile, QR or collaboration-channel compromise', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'Security log deletion or tampering')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Detection Evasion'), N'Security log deletion or tampering', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Detection Evasion'), N'SIEM or alert pipeline overload', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption'), N'Backup destruction or recovery sabotage', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise'), N'Vendor-hosted platform cyber disruption', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Shadow SaaS or personal GenAI data leakage')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering'), N'Shadow SaaS or personal GenAI data leakage', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse'), N'Prompt injection against AI assistant', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse'), N'LLM sensitive disclosure or agent overreach', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse'), N'AI training or retrieval data poisoning', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Encrypted data harvesting or cryptographic downgrade')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering'), N'Encrypted data harvesting or cryptographic downgrade', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse'), N'Lost device or stolen session exposure', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering'), N'Official social media or content publishing takeover', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'OT remote credential theft and session takeover')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse'), N'OT remote credential theft and session takeover', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse'), N'Shared, default or stale OT account abuse', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Access Abuse'), N'Privileged engineering account misuse', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Remote Access Abuse'), N'Vendor remote access compromise', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Jump server or emergency access bypass')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Remote Access Abuse'), N'Jump server or emergency access bypass', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Network Intrusion'), N'IT-to-OT lateral movement', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Service Exploitation'), N'Internet-exposed OT service exploitation', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Workstation Compromise'), N'Engineering workstation compromise', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Logic/Configuration Manipulation'), N'Unauthorized controller logic change', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Controller mode, I/O or drive manipulation')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Logic/Configuration Manipulation'), N'Controller mode, I/O or drive manipulation', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'HMI/SCADA Manipulation'), N'HMI/SCADA setpoint and command manipulation', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'HMI/SCADA Manipulation'), N'Alarm and operator view suppression', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Protocol/Command Abuse'), N'OT protocol command abuse', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND tc.ThreatName = N'Wireless, radio or satellite link abuse')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Wireless/Comms Abuse'), N'Wireless, radio or satellite link abuse', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'OT data and telemetry tampering')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data/Telemetry Abuse'), N'OT data and telemetry tampering', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'Historian and OT documentation exfiltration')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data/Telemetry Abuse'), N'Historian and OT documentation exfiltration', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware'), N'Ransomware on OT support systems', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Destructive wiper or worm propagation')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware'), N'Destructive wiper or worm propagation', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware'), N'ICS-specific malware or firmware implant', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Physical/Portable Media Compromise'), N'Removable media or portable device compromise', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Physical/Portable Media Compromise'), N'Rogue device or physical port abuse', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise'), N'Compromised OT supply chain or hardware', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Service Exploitation'), N'Legacy OT service exploitation', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Unsafe maintenance, scanning or patch disruption')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption'), N'Unsafe maintenance, scanning or patch disruption', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Trust/Crypto Abuse'), N'Cryptographic trust, certificate or key abuse', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption'), N'Time, DNS and infrastructure service manipulation', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Recovery Disruption'), N'Backup and recovery compromise', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Loss of manual fallback or incident containment')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption'), N'Loss of manual fallback or incident containment', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'OT communications or access-layer denial of service')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption'), N'OT communications or access-layer denial of service', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND tc.ThreatName = N'OT monitoring and logging evasion')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Monitoring Evasion'), N'OT monitoring and logging evasion', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Safety System Abuse'), N'Safety system manipulation', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/IIoT Abuse'), N'Cloud, IIoT or edge gateway compromise', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Field Asset Manipulation'), N'Sector-specific connected field asset manipulation', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering'), N'OT personnel social engineering', 1, 0, N'functional_team_excel');
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation')
    INSERT INTO Threat_Catalogue (ThreatTypeID, ThreatName, IsActive, IsDeleted, Source)
    VALUES ((SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse'), N'AI-assisted OT decision or data manipulation', 1, 0, N'functional_team_excel');


-- 4. Threat_Catalogue_Category_Map (per-threat STRIDE links)
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Credential phishing and MFA session theft' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Credential phishing and MFA session theft'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Credential phishing and MFA session theft' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Credential phishing and MFA session theft'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Credential phishing and MFA session theft' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Credential phishing and MFA session theft'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Password spray and credential stuffing' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Password spray and credential stuffing'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Password spray and credential stuffing' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Password spray and credential stuffing'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Password spray and credential stuffing' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Password spray and credential stuffing'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'OAuth consent and refresh-token abuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'OAuth consent and refresh-token abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'OAuth consent and refresh-token abuse' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'OAuth consent and refresh-token abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'OAuth consent and refresh-token abuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'OAuth consent and refresh-token abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'OAuth consent and refresh-token abuse' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'OAuth consent and refresh-token abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Privileged account takeover or misuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, stale or orphaned account misuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Helpdesk identity reset fraud'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Deepfake-enabled executive or vendor fraud' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Deepfake-enabled executive or vendor fraud'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Deepfake-enabled executive or vendor fraud' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Deepfake-enabled executive or vendor fraud'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Deepfake-enabled executive or vendor fraud' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Deepfake-enabled executive or vendor fraud'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Deepfake-enabled executive or vendor fraud' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Deepfake-enabled executive or vendor fraud'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware with data theft extortion'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Wiper or destructive script attack'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Infostealer or remote access malware' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Infostealer or remote access malware'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Infostealer or remote access malware' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Infostealer or remote access malware'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Infostealer or remote access malware' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Infostealer or remote access malware'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Infostealer or remote access malware' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Infostealer or remote access malware'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Remote support and RMM tool abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Software supply chain or vendor update compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'CI/CD and source repository compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Secrets, API key or service credential theft'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Public-facing application or API exploitation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Injection or script execution attack'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Unauthorized API or record access'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Business workflow manipulation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Business workflow manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Business workflow manipulation' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Business workflow manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Business workflow manipulation' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Business workflow manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Business workflow manipulation' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND tc.ThreatName = N'Business workflow manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Authoritative data tampering' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Authoritative data tampering'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Authoritative data tampering' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Authoritative data tampering'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Authoritative data tampering' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Authoritative data tampering'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Authoritative data tampering' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Authoritative data tampering'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Bulk data exfiltration' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Bulk data exfiltration'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Bulk data exfiltration' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Bulk data exfiltration'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Bulk data exfiltration' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Bulk data exfiltration'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Cloud storage or sharing-link exposure' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Cloud storage or sharing-link exposure'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Cloud storage or sharing-link exposure' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Cloud storage or sharing-link exposure'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'Cloud tenant privilege takeover'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND tc.ThreatName = N'SaaS tenant takeover'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DDoS and resource exhaustion attack' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DDoS and resource exhaustion attack'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Bot-driven scraping, fake accounts or workflow abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'DNS, domain or route hijacking'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Man-in-the-middle or certificate abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official messaging channel compromise' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official messaging channel compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official messaging channel compromise' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official messaging channel compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official messaging channel compromise' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official messaging channel compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official messaging channel compromise' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official messaging channel compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Mobile, QR or collaboration-channel compromise' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Mobile, QR or collaboration-channel compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Mobile, QR or collaboration-channel compromise' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Mobile, QR or collaboration-channel compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Mobile, QR or collaboration-channel compromise' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Mobile, QR or collaboration-channel compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Mobile, QR or collaboration-channel compromise' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Mobile, QR or collaboration-channel compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'Security log deletion or tampering' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'Security log deletion or tampering'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'Security log deletion or tampering' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'Security log deletion or tampering'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'Security log deletion or tampering' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'Security log deletion or tampering'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'Security log deletion or tampering' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'Security log deletion or tampering'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Detection Evasion' AND tc.ThreatName = N'SIEM or alert pipeline overload'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Backup destruction or recovery sabotage'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Vendor-hosted platform cyber disruption'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Shadow SaaS or personal GenAI data leakage' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Shadow SaaS or personal GenAI data leakage'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Shadow SaaS or personal GenAI data leakage' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Shadow SaaS or personal GenAI data leakage'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'Prompt injection against AI assistant'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'LLM sensitive disclosure or agent overreach'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI training or retrieval data poisoning'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Encrypted data harvesting or cryptographic downgrade' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Encrypted data harvesting or cryptographic downgrade'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Encrypted data harvesting or cryptographic downgrade' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Encrypted data harvesting or cryptographic downgrade'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Encrypted data harvesting or cryptographic downgrade' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Encrypted data harvesting or cryptographic downgrade'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Encrypted data harvesting or cryptographic downgrade' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND tc.ThreatName = N'Encrypted data harvesting or cryptographic downgrade'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Lost device or stolen session exposure'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'Official social media or content publishing takeover'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'OT remote credential theft and session takeover' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'OT remote credential theft and session takeover'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'OT remote credential theft and session takeover' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'OT remote credential theft and session takeover'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'OT remote credential theft and session takeover' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'OT remote credential theft and session takeover'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'OT remote credential theft and session takeover' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'OT remote credential theft and session takeover'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Credential Abuse' AND tc.ThreatName = N'Shared, default or stale OT account abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND tc.ThreatName = N'Privileged engineering account misuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Vendor remote access compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Jump server or emergency access bypass' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Jump server or emergency access bypass'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Jump server or emergency access bypass' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Jump server or emergency access bypass'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Jump server or emergency access bypass' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Jump server or emergency access bypass'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Jump server or emergency access bypass' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND tc.ThreatName = N'Jump server or emergency access bypass'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND tc.ThreatName = N'IT-to-OT lateral movement'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Internet-exposed OT service exploitation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND tc.ThreatName = N'Engineering workstation compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Unauthorized controller logic change'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Controller mode, I/O or drive manipulation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Controller mode, I/O or drive manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Controller mode, I/O or drive manipulation' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Controller mode, I/O or drive manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Controller mode, I/O or drive manipulation' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Controller mode, I/O or drive manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Controller mode, I/O or drive manipulation' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND tc.ThreatName = N'Controller mode, I/O or drive manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'HMI/SCADA setpoint and command manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND tc.ThreatName = N'Alarm and operator view suppression'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND tc.ThreatName = N'OT protocol command abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND tc.ThreatName = N'Wireless, radio or satellite link abuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND tc.ThreatName = N'Wireless, radio or satellite link abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND tc.ThreatName = N'Wireless, radio or satellite link abuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND tc.ThreatName = N'Wireless, radio or satellite link abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND tc.ThreatName = N'Wireless, radio or satellite link abuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND tc.ThreatName = N'Wireless, radio or satellite link abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND tc.ThreatName = N'Wireless, radio or satellite link abuse' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND tc.ThreatName = N'Wireless, radio or satellite link abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'OT data and telemetry tampering' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'OT data and telemetry tampering'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'OT data and telemetry tampering' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'OT data and telemetry tampering'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'OT data and telemetry tampering' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'OT data and telemetry tampering'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'OT data and telemetry tampering' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'OT data and telemetry tampering'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'Historian and OT documentation exfiltration' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'Historian and OT documentation exfiltration'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'Historian and OT documentation exfiltration' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'Historian and OT documentation exfiltration'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'Historian and OT documentation exfiltration' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND tc.ThreatName = N'Historian and OT documentation exfiltration'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Ransomware on OT support systems'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Destructive wiper or worm propagation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Destructive wiper or worm propagation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Destructive wiper or worm propagation' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Destructive wiper or worm propagation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Destructive wiper or worm propagation' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Destructive wiper or worm propagation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Destructive wiper or worm propagation' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'Destructive wiper or worm propagation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND tc.ThreatName = N'ICS-specific malware or firmware implant'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Removable media or portable device compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND tc.ThreatName = N'Rogue device or physical port abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND tc.ThreatName = N'Compromised OT supply chain or hardware'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND tc.ThreatName = N'Legacy OT service exploitation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Unsafe maintenance, scanning or patch disruption' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Unsafe maintenance, scanning or patch disruption'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Unsafe maintenance, scanning or patch disruption' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Unsafe maintenance, scanning or patch disruption'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Unsafe maintenance, scanning or patch disruption' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Unsafe maintenance, scanning or patch disruption'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND tc.ThreatName = N'Cryptographic trust, certificate or key abuse'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Time, DNS and infrastructure service manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND tc.ThreatName = N'Backup and recovery compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Loss of manual fallback or incident containment' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Loss of manual fallback or incident containment'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Loss of manual fallback or incident containment' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Loss of manual fallback or incident containment'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Loss of manual fallback or incident containment' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'Loss of manual fallback or incident containment'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'OT communications or access-layer denial of service' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'OT communications or access-layer denial of service'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'OT communications or access-layer denial of service' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Service Disruption' AND tc.ThreatName = N'OT communications or access-layer denial of service'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND tc.ThreatName = N'OT monitoring and logging evasion' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND tc.ThreatName = N'OT monitoring and logging evasion'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND tc.ThreatName = N'OT monitoring and logging evasion' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND tc.ThreatName = N'OT monitoring and logging evasion'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND tc.ThreatName = N'OT monitoring and logging evasion' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND tc.ThreatName = N'OT monitoring and logging evasion'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND tc.ThreatName = N'OT monitoring and logging evasion' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND tc.ThreatName = N'OT monitoring and logging evasion'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND tc.ThreatName = N'Safety system manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND tc.ThreatName = N'Cloud, IIoT or edge gateway compromise'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND tc.ThreatName = N'Sector-specific connected field asset manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'Social Engineering' AND tc.ThreatName = N'OT personnel social engineering'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Elevation of Privilege'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation' AND cat.ThreatCategoryName = N'Spoofing')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Spoofing'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation' AND cat.ThreatCategoryName = N'Tampering')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Tampering'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation' AND cat.ThreatCategoryName = N'Repudiation')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Repudiation'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation' AND cat.ThreatCategoryName = N'Information Disclosure')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Information Disclosure'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation' AND cat.ThreatCategoryName = N'Denial of Service')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation'),
        (SELECT ThreatCategoryID FROM Threat_Category WHERE ThreatCategoryName = N'Denial of Service'));
IF NOT EXISTS (SELECT 1 FROM Threat_Catalogue_Category_Map m JOIN Threat_Catalogue tc ON m.ThreatCatalogueID = tc.ThreatCatalogueID JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Category cat ON m.ThreatCategoryID = cat.ThreatCategoryID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation' AND cat.ThreatCategoryName = N'Elevation of Privilege')
    INSERT INTO Threat_Catalogue_Category_Map (ThreatCatalogueID, ThreatCategoryID) VALUES (
        (SELECT tc.ThreatCatalogueID FROM Threat_Catalogue tc JOIN Threat_Type tt ON tc.ThreatTypeID = tt.ThreatTypeID WHERE tt.ThreatTypeName = N'AI Abuse' AND tc.ThreatName = N'AI-assisted OT decision or data manipulation'),
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
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Credential Abuse' AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Credential Abuse' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Credential Abuse' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/SaaS Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/SaaS Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/SaaS Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Credential Abuse' AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Credential Abuse' AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Credential Abuse' AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Credential Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Social Engineering' AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Social Engineering' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Social Engineering' AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Social Engineering' AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND ta.ThreatActorName = N'Ransomware affiliate')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Ransomware affiliate'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Web/API Exploitation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Web/API Exploitation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Web/API Exploitation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Web/API Exploitation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Web/API Exploitation' AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Web/API Exploitation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/SaaS Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Cloud/SaaS Abuse' AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/SaaS Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Service Disruption' AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Service Disruption' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Service Disruption' AND ta.ThreatActorName = N'Hacktivist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Hacktivist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Service Disruption' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Service Disruption' AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Social Engineering' AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Detection Evasion' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Detection Evasion'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Detection Evasion' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Detection Evasion'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Detection Evasion' AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Detection Evasion'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Detection Evasion' AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Detection Evasion'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Service Disruption' AND ta.ThreatActorName = N'Ransomware affiliate')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Ransomware affiliate'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Service Disruption' AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Service Disruption' AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'AI Abuse' AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'AI Abuse' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'AI Abuse' AND ta.ThreatActorName = N'Malicious user')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious user'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'AI Abuse' AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'AI Abuse' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'AI Abuse' AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Social Engineering' AND ta.ThreatActorName = N'Hacktivist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Hacktivist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Access Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Access Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Access Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Access Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Remote Access Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Remote Access Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Remote Access Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Remote Access Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Remote Access Abuse' AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Remote Access Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Network Intrusion'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Network Intrusion'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Network Intrusion'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Service Exploitation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND ta.ThreatActorName = N'Hacktivist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Service Exploitation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Hacktivist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Service Exploitation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'OT Service Exploitation' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Service Exploitation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Workstation Compromise'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Workstation Compromise'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Workstation Compromise'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Workstation Compromise'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Logic/Configuration Manipulation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Logic/Configuration Manipulation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Logic/Configuration Manipulation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Logic/Configuration Manipulation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'HMI/SCADA Manipulation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'HMI/SCADA Manipulation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'HMI/SCADA Manipulation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'HMI/SCADA Manipulation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Protocol/Command Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Protocol/Command Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Protocol/Command Abuse' AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Protocol/Command Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Wireless/Comms Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Wireless/Comms Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Wireless/Comms Abuse' AND ta.ThreatActorName = N'Hacktivist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Wireless/Comms Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Hacktivist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data/Telemetry Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data/Telemetry Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data/Telemetry Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data/Telemetry Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND ta.ThreatActorName = N'Hacktivist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Hacktivist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Physical/Portable Media Compromise'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Physical/Portable Media Compromise'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Physical/Portable Media Compromise'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Physical/Portable Media Compromise'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Physical/Portable Media Compromise'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Trust/Crypto Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Trust/Crypto Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND ta.ThreatActorName = N'Negligent insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Trust/Crypto Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Negligent insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Recovery Disruption'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Recovery Disruption'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Recovery Disruption'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Monitoring Evasion'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Monitoring Evasion'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Monitoring Evasion' AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Monitoring Evasion'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Safety System Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Safety System Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND ta.ThreatActorName = N'External attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/IIoT Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'External attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/IIoT Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/IIoT Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Cloud/IIoT Abuse' AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Cloud/IIoT Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Field Asset Manipulation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND ta.ThreatActorName = N'Cybercriminal')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Field Asset Manipulation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Cybercriminal'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND ta.ThreatActorName = N'Hacktivist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Field Asset Manipulation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Hacktivist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND ta.ThreatActorName = N'Malicious insider')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Field Asset Manipulation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Malicious insider'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Social Engineering' AND ta.ThreatActorName = N'Nation-state/APT')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Social Engineering'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Nation-state/APT'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'AI Abuse' AND ta.ThreatActorName = N'Third-party/Vendor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'AI Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Third-party/Vendor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Service Disruption' AND ta.ThreatActorName = N'Terrorist/Extremist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Service Disruption'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Terrorist/Extremist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND ta.ThreatActorName = N'Terrorist/Extremist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Safety System Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Terrorist/Extremist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'HMI/SCADA Manipulation' AND ta.ThreatActorName = N'Terrorist/Extremist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'HMI/SCADA Manipulation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Terrorist/Extremist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND ta.ThreatActorName = N'Terrorist/Extremist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Field Asset Manipulation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Terrorist/Extremist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'OT Network Intrusion' AND ta.ThreatActorName = N'Terrorist/Extremist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'OT Network Intrusion'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Terrorist/Extremist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Recovery Disruption' AND ta.ThreatActorName = N'Terrorist/Extremist')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Recovery Disruption'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Terrorist/Extremist'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data Theft/Tampering' AND ta.ThreatActorName = N'Industrial Spy/Competitor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data Theft/Tampering'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Industrial Spy/Competitor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Access Abuse' AND ta.ThreatActorName = N'Industrial Spy/Competitor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Access Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Industrial Spy/Competitor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND ta.ThreatActorName = N'Industrial Spy/Competitor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Workstation Compromise'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Industrial Spy/Competitor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Data/Telemetry Abuse' AND ta.ThreatActorName = N'Industrial Spy/Competitor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Data/Telemetry Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Industrial Spy/Competitor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND ta.ThreatActorName = N'Industrial Spy/Competitor')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Trust/Crypto Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Industrial Spy/Competitor'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Supply Chain Compromise' AND ta.ThreatActorName = N'Supply Chain Attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Supply Chain Compromise'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Supply Chain Attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Logic/Configuration Manipulation' AND ta.ThreatActorName = N'Supply Chain Attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Logic/Configuration Manipulation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Supply Chain Attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Malware/Ransomware' AND ta.ThreatActorName = N'Supply Chain Attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Malware/Ransomware'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Supply Chain Attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Trust/Crypto Abuse' AND ta.ThreatActorName = N'Supply Chain Attacker')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Trust/Crypto Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Supply Chain Attacker'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Physical/Portable Media Compromise' AND ta.ThreatActorName = N'Physical Intruder/Saboteur')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Physical/Portable Media Compromise'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Physical Intruder/Saboteur'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Safety System Abuse' AND ta.ThreatActorName = N'Physical Intruder/Saboteur')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Safety System Abuse'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Physical Intruder/Saboteur'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Field Asset Manipulation' AND ta.ThreatActorName = N'Physical Intruder/Saboteur')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Field Asset Manipulation'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Physical Intruder/Saboteur'));
IF NOT EXISTS (SELECT 1 FROM ThreatType_ThreatActor_Map m JOIN Threat_Type tt ON m.ThreatTypeID = tt.ThreatTypeID JOIN Threat_Actor ta ON m.ThreatActorID = ta.ThreatActorID WHERE tt.ThreatTypeName = N'Engineering Workstation Compromise' AND ta.ThreatActorName = N'Physical Intruder/Saboteur')
    INSERT INTO ThreatType_ThreatActor_Map (ThreatTypeID, ThreatActorID) VALUES (
        (SELECT ThreatTypeID FROM Threat_Type WHERE ThreatTypeName = N'Engineering Workstation Compromise'),
        (SELECT ThreatActorID FROM Threat_Actor WHERE ThreatActorName = N'Physical Intruder/Saboteur'));

-- 7. Removed. Every sector-visible candidate reaches the LLM validator, which
-- decides relevance, so no exemption tier is needed.

-- Verify
SELECT (SELECT COUNT(*) FROM Threat_Category) AS categories, (SELECT COUNT(*) FROM Threat_Type WHERE Source = N'functional_team_excel') AS types,
       (SELECT COUNT(*) FROM Threat_Catalogue WHERE Source = N'functional_team_excel') AS catalogue_entries, (SELECT COUNT(*) FROM Threat_Actor) AS actors,
       (SELECT COUNT(*) FROM Threat_Catalogue_Category_Map) AS category_links, (SELECT COUNT(*) FROM ThreatType_ThreatActor_Map) AS actor_links;
