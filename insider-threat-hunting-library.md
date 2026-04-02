# Insider Threat Hunting Library
### KQL Prompt Library for Microsoft Sentinel & Defender Advanced Hunting

**Version:** 1.0 — 2026-03-31
**Framework:** CMU CERT Insider Threat Framework + MITRE ATT&CK Enterprise
**Compatibility:** Microsoft Sentinel (Log Analytics), Microsoft Defender XDR Advanced Hunting

---

## Contents

1. [Introduction](#introduction)
2. [Master KQL Generation Prompt](#master-kql-generation-prompt)
3. [Insider Threat Scenario Library](#insider-threat-scenario-library)
   - [Category A: Data Theft](#category-a-data-theft)
   - [Category B: Sabotage](#category-b-sabotage)
   - [Category C: Fraud](#category-c-fraud)
   - [Category D: Espionage](#category-d-espionage)
   - [Category E: Unintentional Insider Threat](#category-e-unintentional-insider-threat)
4. [Quick Reference](#quick-reference)
5. [How to Run Queries](#how-to-run-queries)

---

## Introduction

This library provides ready-to-use hunting prompts designed for analysts investigating insider threats across enterprise Microsoft environments. Each scenario targets behaviors observed in real CMU CERT insider threat cases and maps directly to MITRE ATT&CK techniques and Microsoft Sentinel or Defender XDR data sources.

### How to use this library

**With an AI assistant (Claude, ChatGPT, Copilot, etc.)**

1. Copy the **Master KQL Generation Prompt** from Section 2.
2. Append any scenario description from Section 3, or write your own in plain English.
3. Paste the combined text into your AI tool of choice.
4. The AI will return a structured JSON block containing the KQL query, MITRE mapping, explanation, false positives, response actions, and hunting tips.
5. Extract the `query` field and run it in Sentinel or Defender Advanced Hunting (see Section 5).

**With KQL Hunt Gen**

If you are using the companion web app (`index.html` in this repository), paste any scenario description directly into the behavior field. The Master Prompt is already loaded. Adjust the table hint, time range, and severity to match your environment before generating.

**Without an AI assistant**

Each scenario includes the expected MITRE techniques and recommended tables. Use these as starting points for manual query construction or to seed searches in existing detection libraries (Sigma, Microsoft Sentinel Community, Elastic).

### Scope and limitations

These prompts produce hunting queries, not detection rules. Hunting queries are designed for analyst-driven, hypothesis-based investigation over historical data. Before promoting any query to a scheduled analytic rule, validate it against your environment's baseline, tune threshold values, and confirm appropriate table retention windows.

Queries target Microsoft-native data sources. Organizations using third-party SIEM or EDR products may need to adapt table names and field mappings.

---

## Master KQL Generation Prompt

Copy the block below in its entirety. Append your threat scenario description at the bottom where indicated. Submit to any AI assistant that accepts natural language instructions.

---

```
You are an expert Microsoft Sentinel threat hunter and KQL engineer with deep knowledge
of MITRE ATT&CK Enterprise and the CMU CERT Insider Threat Framework.

When given a description of suspicious behavior, respond with a JSON object ONLY —
no markdown fences, no prose outside the JSON. The JSON must conform exactly to this schema:

{
  "query": "<complete, production-ready KQL query>",
  "severity": "High | Medium | Low | Informational",
  "mitre": [
    {
      "id": "T####.###",
      "name": "Technique Name",
      "tactic": "Tactic Name"
    }
  ],
  "what": "<1-2 sentence summary of what the query detects>",
  "how": "<2-4 sentences explaining how the KQL logic works>",
  "why": "<1-2 sentences on why this pattern indicates threat activity>",
  "falsePositives": ["<fp1>", "<fp2>", "<fp3>"],
  "responseActions": ["<action1>", "<action2>", "<action3>"],
  "huntingTips": ["<tip1>", "<tip2>"]
}

KQL quality requirements:
- Use the most appropriate Sentinel / Defender XDR table(s) for the behavior described.
- Always include a time filter using ago(). Default to ago(30d) unless a timeRange is specified.
- Use let bindings to name intermediate datasets and improve readability.
- Add // comments on non-obvious logic.
- Use summarize + extend for aggregations; project or project-rename at the end to return
  clean, analyst-friendly column names.
- Handle case-insensitivity with =~ or tolower() where appropriate.
- Use join or union when correlation across multiple tables adds detection value.
- Produce queries that run without modification in Log Analytics / Advanced Hunting —
  no pseudo-code, no placeholder values except clearly marked thresholds.
- Prefer DeviceProcessEvents for endpoint process behavior, SecurityEvent for Windows
  Security log events, SigninLogs for Azure AD authentication.
- If a tableHint is provided, use it as the primary table.
- Substitute timeRange values into ago() literally (e.g., "30d" → ago(30d)).

---

Threat behavior to hunt:
[PASTE YOUR SCENARIO DESCRIPTION HERE]

Parameters:
- timeRange: 30d
- tableHint: auto
- severityOverride: auto

Respond with the JSON object only.
```

---

## Insider Threat Scenario Library

Each scenario includes:
- **Behavior description** — paste directly into the Master Prompt
- **MITRE techniques** — expected mappings for validation
- **Primary tables** — recommended Sentinel / Defender XDR tables

---

### Category A: Data Theft

Data theft cases account for the majority of CMU CERT insider incidents. Common patterns include bulk file staging, cloud sync abuse, removable media exfiltration, and anomalous email forwarding established before resignation.

---

#### A-1 — Bulk File Staging Before Departure

**Behavior description**
```
A user who recently submitted a resignation or who HR has flagged as a flight risk is
copying large volumes of files from network shares or SharePoint to a local staging
directory (Desktop, Downloads, or a newly created folder) in the days before their last
date. Detect abnormal spikes in file read or copy events for this user compared to their
30-day baseline, particularly targeting document types (.docx, .xlsx, .pdf, .pptx, .zip).
```

**Expected MITRE techniques**

| ID | Technique | Tactic |
|----|-----------|--------|
| T1005 | Data from Local System | Collection |
| T1039 | Data from Network Shared Drive | Collection |
| T1560 | Archive Collected Data | Collection |

**Primary tables**
- `DeviceFileEvents` (MDE) — file copy/read events
- `OfficeActivity` — SharePoint and OneDrive file access
- `CloudAppEvents` — M365 Defender cloud file operations

---

#### A-2 — Personal Cloud Storage Sync During Business Hours

**Behavior description**
```
Detect employees uploading files to personal cloud storage services (Dropbox, Google Drive,
Box, iCloud, WeTransfer, or similar) from a corporate device or via the corporate network
proxy. Focus on sustained or high-volume upload sessions, especially when the destination
domain is not on the corporate approved-list and the file types include documents,
spreadsheets, archives, or source code.
```

**Expected MITRE techniques**

| ID | Technique | Tactic |
|----|-----------|--------|
| T1567.002 | Exfiltration to Cloud Storage | Exfiltration |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |

**Primary tables**
- `DeviceNetworkEvents` — outbound connections by destination domain
- `CommonSecurityLog` — proxy/firewall logs (CEF format)
- `DeviceFileEvents` — correlated file access prior to upload

---

#### A-3 — USB/Removable Media Mass Copy

**Behavior description**
```
A user connects a removable storage device (USB drive, external hard drive, SD card) to
a corporate endpoint and copies a large number of files or a high total byte volume within
a short window. Flag cases where removable media usage is uncommon for this user or this
device class, and correlate with file types associated with intellectual property
(.dwg, .c, .py, .sql, .key, .cer, .pfx, .zip, .tar).
```

**Expected MITRE techniques**

| ID | Technique | Tactic |
|----|-----------|--------|
| T1052.001 | Exfiltration over USB | Exfiltration |
| T1005 | Data from Local System | Collection |

**Primary tables**
- `DeviceEvents` — `RemovableStoragePolicyTriggered` and `UsbDriveMounted` action types
- `DeviceFileEvents` — file writes to removable media paths
- `SecurityEvent` — Event ID 4663 (object access on removable drives, if audited)

---

#### A-4 — Email Auto-Forward Rule to External Address

**Behavior description**
```
Detect mailbox rules that automatically forward or redirect a copy of all incoming or
outgoing email to an external (non-corporate) email address. Flag rules created or
modified within the past 30 days, particularly for users in privileged roles, sales,
R&D, legal, or finance. Include cases where the rule name is obfuscated or blank, or
where the forward destination is a free webmail provider.
```

**Expected MITRE techniques**

| ID | Technique | Tactic |
|----|-----------|--------|
| T1114.003 | Email Forwarding Rule | Collection |
| T1114.001 | Local Email Collection | Collection |

**Primary tables**
- `OfficeActivity` — `New-InboxRule` and `Set-InboxRule` operations
- `AuditLogs` (Azure AD) — Exchange admin audit events
- `CloudAppEvents` — M365 Defender mailbox rule changes

---

#### A-5 — Source Code Repository Cloning by Non-Engineering Account

**Behavior description**
```
Detect non-engineering or recently offboarded accounts performing git clone, git pull,
or API-based repository download operations against internal or hosted source control
systems (Azure DevOps, GitHub Enterprise, GitLab). Flag accounts whose job role does not
typically access repositories (HR, finance, marketing, executive assistants) and any
account that clones more repositories than their 30-day norm within a single session.
```

**Expected MITRE techniques**

| ID | Technique | Tactic |
|----|-----------|--------|
| T1213.003 | Code Repositories | Collection |
| T1530 | Data from Cloud Storage | Collection |

**Primary tables**
- `AuditLogs` — Azure DevOps and GitHub Enterprise audit events (if ingested)
- `DeviceNetworkEvents` — connections to internal SCM hostnames
- `OfficeActivity` — SharePoint-hosted repository access

---

### Category B: Sabotage

Sabotage cases typically involve disgruntled employees or contractors deleting critical data, modifying configurations, or planting logic bombs. Activity often occurs outside normal hours and targets systems the actor previously had legitimate access to.

---

#### B-1 — Mass File Deletion Outside Business Hours

**Behavior description**
```
Detect a user or service account performing a high volume of file delete operations
(delete, overwrite, or move to Recycle Bin) within a short time window, particularly
outside of normal business hours (before 07:00 or after 20:00 local time, or on
weekends). Correlate with whether the account has recently been subject to a disciplinary
action, PIP, or involuntary termination flag in HR data if available. Focus on deletions
targeting shared drives, project directories, or backup locations.
```

**Expected MITRE techniques**

| ID | Technique | Tactic |
|----|-----------|--------|
| T1485 | Data Destruction | Impact |
| T1490 | Inhibit System Recovery | Impact |
| T1078 | Valid Accounts | Defense Evasion |

**Primary tables**
- `DeviceFileEvents` — `FileDeleted` action type
- `SecurityEvent` — Event ID 4663 with delete access mask
- `OfficeActivity` — `FileDeleted` and `FileRecycled` operations

---

#### B-2 — Database Record Deletion or Truncation

**Behavior description**
```
Detect execution of destructive SQL statements (DELETE, TRUNCATE, DROP TABLE) against
production databases by accounts that do not routinely perform such operations. Flag
cases where the statement affects more than a threshold number of rows, where the
operation is not preceded by a BEGIN TRANSACTION (indicating no intent to roll back),
or where execution occurs outside a change window. Include stored procedure calls that
wrap destructive operations.
```

**Expected MITRE techniques**

| ID | Technique | Tactic |
|----|-----------|--------|
| T1485 | Data Destruction | Impact |
| T1565.001 | Stored Data Manipulation | Impact |

**Primary tables**
- `AzureDiagnostics` — Azure SQL / SQL Managed Instance audit logs
- `CommonSecurityLog` — database activity monitoring (DAM) CEF events
- `Syslog` — PostgreSQL/MySQL audit logs on Linux hosts

---

#### B-3 — Scheduled Task or Cron Job Created as Logic Bomb

**Behavior description**
```
Detect scheduled tasks (Windows Task Scheduler) or cron jobs created by user accounts
— rather than service accounts or software installers — that are configured to execute
scripts, binaries, or PowerShell commands at a future date/time or on a recurring
schedule. Flag tasks that reference temp directories, encoded commands, user profile
paths, or that are created outside patch/deployment windows and are not associated with
known software installation activity.
```

**Expected MITRE techniques**

| ID | Technique | Tactic |
|----|-----------|--------|
| T1053.005 | Scheduled Task | Persistence |
| T1053.003 | Cron | Persistence |
| T1059.001 | PowerShell | Execution |

**Primary tables**
- `DeviceProcessEvents` — `schtasks.exe` and `at.exe` process creation
- `SecurityEvent` — Event ID 4698 (scheduled task created), 4702 (updated)
- `Syslog` — cron daemon log entries on Linux endpoints

---

### Category C: Fraud

Fraud cases involve employees manipulating financial systems, benefits data, procurement records, or customer accounts for personal gain. These behaviors often abuse legitimate access and may not trigger signature-based controls.

---

#### C-1 — Anomalous Financial Transaction Approval by Single Approver

**Behavior description**
```
Detect cases where a single user both initiates and approves a financial transaction
(purchase order, vendor payment, expense claim, or payroll adjustment) in a system that
is supposed to enforce segregation of duties. Flag transactions above a defined dollar
threshold, transactions approved within an unusually short time after submission, and
any transactions where the approver and submitter share the same manager or team in
directory data.
```

**Expected MITRE techniques**

| ID | Technique | Tactic |
|----|-----------|--------|
| T1565.001 | Stored Data Manipulation | Impact |
| T1078.002 | Domain Accounts | Defense Evasion |

**Primary tables**
- `AuditLogs` — Azure AD application audit events for ERP/financial apps
- `OfficeActivity` — SharePoint-hosted financial document modifications
- `CloudAppEvents` — M365 Defender access to financial application URLs

---

#### C-2 — Repeated Access to Colleague or Customer PII Records Without Case Association

**Behavior description**
```
Detect employees who are querying or viewing personally identifiable information (PII)
records — customer accounts, HR employee files, patient records, or benefits data —
at a rate significantly above their peer group baseline, or who are accessing records
for individuals not associated with any open case, ticket, or customer interaction
assigned to them. Focus on bulk record lookups performed within a single session.
```

**Expected MITRE techniques**

| ID | Technique | Tactic |
|----|-----------|--------|
| T1213 | Data from Information Repositories | Collection |
| T1078 | Valid Accounts | Defense Evasion |

**Primary tables**
- `AuditLogs` — Azure AD and application audit logs
- `CloudAppEvents` — application-specific record access events
- `OfficeActivity` — SharePoint list and library access

---

### Category D: Espionage

Espionage cases involve the deliberate collection of sensitive organizational, government, or competitive intelligence for transfer to an external entity (foreign government, competitor, or unauthorized third party). Indicators often overlap with data theft but with a focus on classified, regulated, or strategically sensitive data classes.

---

#### D-1 — Access to Sensitive Projects Beyond Job Scope Followed by External Contact

**Behavior description**
```
Detect a user accessing classified project directories, restricted SharePoint sites, or
data rooms that are outside their normal job scope — particularly projects related to
M&A activity, government contracts, product roadmaps, or defense research — where the
same user also generates outbound email or network connections to personal webmail,
encrypted messaging apps, or IP ranges associated with foreign entities within the
same 24-hour window.
```

**Expected MITRE techniques**

| ID | Technique | Tactic |
|----|-----------|--------|
| T1213 | Data from Information Repositories | Collection |
| T1567 | Exfiltration Over Web Service | Exfiltration |
| T1071.003 | Mail Protocols | Command and Control |

**Primary tables**
- `OfficeActivity` — SharePoint site and file access
- `DeviceNetworkEvents` — outbound connections to webmail and messaging domains
- `EmailEvents` — outbound email recipient domains

---

#### D-2 — Printing or Screenshot of Sensitive Documents

**Behavior description**
```
Detect users printing, taking screenshots of, or using screen capture tools against
documents that are classified or labeled as Confidential, Restricted, or containing
export-controlled data (ITAR, EAR, CUI). Flag print jobs sent to non-networked or
personal printers, screenshot tool execution (Snipping Tool, Greenshot, ShareX,
print screen key events) immediately following access to labeled documents, and
any document download from a DLP-monitored repository.
```

**Expected MITRE techniques**

| ID | Technique | Tactic |
|----|-----------|--------|
| T1113 | Screen Capture | Collection |
| T1005 | Data from Local System | Collection |

**Primary tables**
- `DeviceProcessEvents` — screenshot tool process creation
- `DeviceEvents` — print job events (`PrintJobCreated` action type)
- `CloudAppEvents` — Microsoft Purview sensitivity label activity

---

#### D-3 — Reconnaissance of Privileged Accounts and Group Memberships

**Behavior description**
```
Detect a standard user account performing LDAP or Active Directory queries to enumerate
privileged group memberships (Domain Admins, Enterprise Admins, security groups for
sensitive projects), user account attributes, or computer objects at an abnormal rate.
Flag use of net.exe, dsquery, AdFind, BloodHound collectors, or PowerShell
ActiveDirectory module commands (Get-ADGroupMember, Get-ADUser) by non-IT accounts.
```

**Expected MITRE techniques**

| ID | Technique | Tactic |
|----|-----------|--------|
| T1069.002 | Domain Groups | Discovery |
| T1087.002 | Domain Account | Discovery |
| T1018 | Remote System Discovery | Discovery |

**Primary tables**
- `DeviceProcessEvents` — `net.exe`, `dsquery.exe`, `adfind.exe`, PowerShell
- `IdentityQueryEvents` — LDAP queries (Microsoft Defender for Identity)
- `SecurityEvent` — Event ID 4661 (SAM object access)

---

### Category E: Unintentional Insider Threat

Unintentional insiders cause harm through negligence, policy violations, or social engineering without malicious intent. These cases are the most common insider threat category and produce the highest volume of incidents. Detection focuses on risky behaviors that create exposure regardless of intent.

---

#### E-1 — Corporate Credentials Entered on Phishing or Lookalike Domain

**Behavior description**
```
Detect cases where a user navigates to a domain that closely resembles a corporate,
partner, or SaaS application domain (typosquatting, homograph attack, or lookalike
registration) and where the HTTP session includes a POST request consistent with
credential submission. Correlate with Azure AD sign-in events from unusual IP addresses
or locations occurring within 30 minutes of the suspicious web visit, indicating the
credentials may have been replayed.
```

**Expected MITRE techniques**

| ID | Technique | Tactic |
|----|-----------|--------|
| T1566.002 | Spearphishing Link | Initial Access |
| T1078 | Valid Accounts | Defense Evasion |
| T1539 | Steal Web Session Cookie | Credential Access |

**Primary tables**
- `DeviceNetworkEvents` — connections to lookalike domains
- `SigninLogs` — Azure AD sign-ins from new IP/location after suspicious browse
- `DeviceEvents` — browser process network activity

---

#### E-2 — Sharing Sensitive Files with Personal or External Email

**Behavior description**
```
Detect users sharing SharePoint files, OneDrive folders, or Teams files externally
using "Anyone with the link" permissions or by explicitly sharing with a personal
email address (gmail.com, outlook.com, yahoo.com, protonmail.com, or other free
providers). Prioritize files with Confidential or higher sensitivity labels, files
in HR, Legal, Finance, or R&D site collections, and sharing events occurring
outside business hours.
```

**Expected MITRE techniques**

| ID | Technique | Tactic |
|----|-----------|--------|
| T1567.002 | Exfiltration to Cloud Storage | Exfiltration |
| T1048.003 | Exfiltration Over Unencrypted Protocol | Exfiltration |

**Primary tables**
- `OfficeActivity` — `SharingSet`, `AnonymousLinkCreated`, `AddedToSecureLink`
- `CloudAppEvents` — M365 Defender file sharing events
- `AuditLogs` — Azure AD B2B guest invitation events

---

#### E-3 — Installation of Unauthorized Remote Access or Tunneling Tools

**Behavior description**
```
Detect installation or execution of unauthorized remote access tools — including
AnyDesk, TeamViewer, Ngrok, Cloudflare Tunnel, Tailscale, ZeroTier, or similar
peer-to-peer or tunneling utilities — on corporate endpoints. Flag cases where the
binary is not present in the corporate software inventory, where the process is
launched from a user's Downloads or AppData directory, or where the tool establishes
an outbound persistent connection to a relay infrastructure IP or domain.
```

**Expected MITRE techniques**

| ID | Technique | Tactic |
|----|-----------|--------|
| T1219 | Remote Access Software | Command and Control |
| T1572 | Protocol Tunneling | Command and Control |
| T1105 | Ingress Tool Transfer | Command and Control |

**Primary tables**
- `DeviceProcessEvents` — process creation for known RAT/tunnel binary names
- `DeviceNetworkEvents` — outbound connections to known relay domains/IP ranges
- `DeviceFileEvents` — binary drops to user-writable paths

---

## Quick Reference

### Insider Threat Indicator → MITRE ATT&CK → KQL Table Mapping

| Indicator | MITRE ID | Technique | Best Table(s) |
|-----------|----------|-----------|---------------|
| Bulk file copy to local staging | T1005 | Data from Local System | `DeviceFileEvents` |
| Network share enumeration and download | T1039 | Data from Network Shared Drive | `DeviceFileEvents`, `SecurityEvent` |
| Upload to personal cloud storage | T1567.002 | Exfiltration to Cloud Storage | `DeviceNetworkEvents`, `CommonSecurityLog` |
| USB mass copy | T1052.001 | Exfiltration over USB | `DeviceEvents`, `DeviceFileEvents` |
| Email auto-forward rule | T1114.003 | Email Forwarding Rule | `OfficeActivity`, `AuditLogs` |
| Printing sensitive documents | T1113 | Screen Capture | `DeviceEvents`, `CloudAppEvents` |
| Scheduled task / cron persistence | T1053.005 | Scheduled Task | `DeviceProcessEvents`, `SecurityEvent` |
| Mass file deletion | T1485 | Data Destruction | `DeviceFileEvents`, `SecurityEvent` |
| Database truncation / destruction | T1485 | Data Destruction | `AzureDiagnostics`, `CommonSecurityLog` |
| SharePoint / repo bulk access | T1213 | Data from Information Repositories | `OfficeActivity`, `AuditLogs` |
| AD group enumeration | T1069.002 | Domain Groups | `IdentityQueryEvents`, `DeviceProcessEvents` |
| Account enumeration | T1087.002 | Domain Account | `IdentityQueryEvents`, `SecurityEvent` |
| Credential stuffing after phish | T1078 | Valid Accounts | `SigninLogs`, `DeviceNetworkEvents` |
| Unauthorized RAT / tunnel tool | T1219 | Remote Access Software | `DeviceProcessEvents`, `DeviceNetworkEvents` |
| Anomalous after-hours activity | T1078 | Valid Accounts | `SigninLogs`, `DeviceLogonEvents` |
| External file sharing | T1567.002 | Exfiltration to Cloud Storage | `OfficeActivity`, `CloudAppEvents` |
| Source code repository cloning | T1213.003 | Code Repositories | `AuditLogs`, `DeviceNetworkEvents` |
| Screenshot of sensitive content | T1113 | Screen Capture | `DeviceProcessEvents` |
| PII record over-access | T1213 | Data from Information Repositories | `AuditLogs`, `CloudAppEvents` |
| Protocol tunneling | T1572 | Protocol Tunneling | `DeviceNetworkEvents` |

### CMU CERT Category → Hunting Priority Matrix

| Category | Typical Actor | Timing Pattern | Detection Difficulty | Priority Scenarios |
|----------|--------------|---------------|---------------------|-------------------|
| Data Theft | Departing employee, contractor | 0–30 days before departure | Medium | A-1, A-2, A-3, A-4, A-5 |
| Sabotage | Disgruntled, recently disciplined | After disciplinary event or notice | High | B-1, B-2, B-3 |
| Fraud | Financially motivated employee | Sustained, low-and-slow | High | C-1, C-2 |
| Espionage | Recruited or ideologically motivated | Long dwell, low volume | Very High | D-1, D-2, D-3 |
| Unintentional | Any employee, highest volume | Random, opportunistic | Low–Medium | E-1, E-2, E-3 |

---

## How to Run Queries

### Microsoft Sentinel — Log Analytics

1. Navigate to **Microsoft Sentinel** in the Azure portal.
2. Select your workspace, then open **Logs** from the left navigation pane.
3. Paste the KQL query into the query editor.
4. Adjust the `ago()` time filter as needed — note that table retention limits apply (default 90 days for most tables; 2 years with long-term retention enabled).
5. Click **Run**. For large time ranges or high-volume tables, scope with an initial `where AccountName == "target_user"` filter before full deployment.
6. To save as a hunting query: select **Save → Save as query**, choose the **Hunting Queries** category, and add applicable MITRE ATT&CK tactics.
7. To promote to a scheduled rule: select **New alert rule → Create Microsoft Sentinel alert** from the query result toolbar.

**Table availability notes**

- `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents` — require Microsoft Defender for Endpoint (MDE) integration and the **Microsoft Defender XDR** data connector enabled in Sentinel.
- `IdentityQueryEvents`, `IdentityLogonEvents`, `IdentityDirectoryEvents` — require Microsoft Defender for Identity (MDI) integration.
- `CloudAppEvents` — requires Microsoft Defender for Cloud Apps integration.
- `SigninLogs`, `AuditLogs` — require the **Azure Active Directory** data connector.
- `OfficeActivity` — requires the **Microsoft 365** data connector.

### Microsoft Defender XDR — Advanced Hunting

1. Navigate to **Microsoft Defender** portal → **Hunting** → **Advanced hunting**.
2. Paste the KQL query into the query editor.
3. The default time range selector caps at **30 days**. For longer lookbacks, use `ago()` in the query and ensure your organization's data retention policy covers the window.
4. Click **Run query**. Results are limited to 10,000 rows per run in the UI; use `summarize` or `top` operators to stay within this limit during exploration.
5. To create a detection rule from a query: click **Create detection rule** in the results toolbar. Set the run frequency (recommended: every 24 hours for insider threat scenarios) and configure alert severity and MITRE mappings.
6. To export results: click **Export** → CSV for offline analysis or case documentation.

**Advanced Hunting table scope**

Advanced Hunting provides direct access to the full `Device*` table family, `Identity*` tables, `Email*` tables, and `CloudAppEvents` without connector configuration. It does not natively include `SecurityEvent`, `Syslog`, `CommonSecurityLog`, or `AzureDiagnostics` — those require Sentinel with the appropriate data connectors.

### Threshold Tuning Recommendations

Before scheduling any insider threat hunting query as a recurring analytic rule:

- **Establish a baseline.** Run the query over a 30-day historical window on the full user population before targeting individuals. Understand the normal distribution of the activity being measured.
- **Use percentile thresholds.** Replace hard-coded count thresholds with dynamic thresholds based on `percentile()` or `stdev()` over a baseline period.
- **Scope to risky populations first.** Prioritize alerts for users on HR watchlists (departing employees, PIPs, recent disciplinary actions) if your organization has a process for joining HR data to security telemetry.
- **Correlate, do not alert in isolation.** A single high file-copy count has moderate specificity. Combined with an after-hours logon, a new USB mount, and a resignation flag, specificity increases substantially. Build correlation queries before deploying as alerting rules.

---

*This document is intended for use by security analysts, threat hunters, and SOC leads in organizations operating Microsoft Sentinel or Microsoft Defender XDR. Scenarios are based on publicly documented CMU CERT insider threat case patterns and MITRE ATT&CK Enterprise framework mappings. Queries generated from these prompts should be validated against your organization's environment before operational deployment.*

*CMU CERT Insider Threat Framework reference: https://www.sei.cmu.edu/our-work/projects/display.cfm?customel_datapageid_4050=21274*
*MITRE ATT&CK Enterprise: https://attack.mitre.org/matrices/enterprise/*
