# KQL Hunt Gen
### AI-Assisted Threat Hunting Query Generator for Microsoft Sentinel

![Platform](https://img.shields.io/badge/Platform-Web%20%28Client--Side%29-blue)
![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20%2B%20CMU%20CERT-red)
![Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Overview

KQL Hunt Gen is a zero-dependency, fully client-side web application that helps SOC analysts and threat hunters generate production-ready KQL (Kusto Query Language) queries for Microsoft Sentinel without needing to know KQL syntax. An analyst describes suspicious behavior in plain English, the tool builds a structured AI prompt, and the resulting KQL query — along with its MITRE ATT&CK mapping, false positive guidance, and response actions — is rendered directly in the browser.

The tool is aligned to two industry-standard frameworks:

- **MITRE ATT&CK Enterprise** — for external adversary tactics, techniques, and procedures
- **CMU CERT Insider Threat Framework** — covering IP theft, IT sabotage, fraud, and espionage categories

Everything runs in the browser. No server, no backend, no API keys stored anywhere. The only outbound network calls are when a user voluntarily copies a prompt and pastes it into an external AI provider.

---

## How It Was Built

This project started as a personal tooling problem: writing KQL queries from scratch for every new hunt is slow, and not every analyst on a team has deep KQL expertise. The goal was to create a bridge — something that lets an analyst describe what they're looking for in plain language and receive a query they can immediately drop into Sentinel.

### Architecture Decision: Client-Side Only

The deliberate choice to build this as a single HTML file with no backend, no npm, no build step was intentional. The tool needed to be:

- **Portable** — double-click and it works, no setup
- **Air-gappable** — usable in environments where internet access is restricted or tooling approval is slow
- **Auditable** — the entire codebase is in one file; nothing is hidden

This meant vanilla JavaScript, inline CSS, and no external dependencies whatsoever.

### The Prompt Engineering Layer

The core of the tool is a carefully structured system prompt embedded in the JavaScript (`INSTRUCTIONS` constant). It instructs the AI to:

1. Act as a Microsoft Sentinel KQL engineer
2. Apply the CMU CERT Insider Threat Framework categories to insider threat scenarios
3. Return a **strictly structured JSON object** — no prose, no markdown fences — containing the query, MITRE mappings, explanation fields, false positives, response actions, and hunting tips

The JSON-only output requirement was critical. It allows the tool to parse the AI response deterministically and render each field into its own UI section rather than dumping raw text.

The prompt template is parameterized at build time with three analyst-controlled variables:
- `tableHint` — target Sentinel/MDE table, or auto-detect
- `timeRange` — sliding window (1d, 7d, 14d, 30d, 90d)
- `severityOverride` — expected alert severity, or auto-detect

### Workflow Design

Because this tool doesn't call AI APIs directly (to avoid requiring API keys and to keep the tool usable with any AI provider), the workflow is a three-step copy-paste loop:

```
1. Analyst describes behavior → tool builds structured prompt
2. Analyst copies prompt → pastes into AI of choice → copies JSON response
3. Analyst pastes response → tool parses JSON → renders formatted results
```

This approach works with Claude, ChatGPT, Gemini, Microsoft Copilot, or Perplexity — the tool has a provider selector that opens the chosen AI in a new tab.

### PDF Import Feature

A later addition to the tool was the PDF import feature. Analysts frequently receive threat intelligence as PDF reports, incident exports, or alert summaries. Instead of manually re-typing IOC values and behavioral descriptions into the hunt input, the PDF parser:

1. Reads the PDF client-side using the browser's built-in file APIs
2. Extracts raw text
3. Runs regex-based IOC detection for IPs, domains, hashes, CVEs, file paths, and MITRE tactic keywords
4. Auto-populates the hunt description field with a generated summary of the threat behavior

The PDF extraction is entirely local — the file never leaves the browser.

### KQL Syntax Highlighting

The KQL output is rendered with a lightweight client-side syntax highlighter built specifically for KQL. It applies color classes to:

- Keywords (`let`, `where`, `project`, `summarize`, `extend`, `join`, `union`)
- Functions (`ago()`, `tolower()`, `contains`, `startswith`)
- Operators (`==`, `!=`, `=~`, `|`)
- String literals, comments, table names, and variable references

This was implemented with a series of regex passes over the query string, replacing matched tokens with `<span>` elements carrying CSS color classes. No external syntax highlighting library was used.

### MITRE ATT&CK Display

Each AI response includes a `mitre` array of technique objects. The tool renders these as individual cards showing the technique ID, name, and tactic — styled to visually distinguish them from the rest of the output. Technique IDs link conceptually to the ATT&CK framework (though not as hyperlinks, to avoid unintentional outbound navigation in restricted environments).

### Export System

Completed hunting packages can be exported as a `.md` (Markdown) file containing:

- A generated hunt ID (timestamp-based)
- The original behavior description
- The full KQL query in a fenced code block
- MITRE ATT&CK technique table
- Explanation sections (what/how/why)
- False positives list
- Response actions
- Hunting tips

This format is designed to be dropped directly into a JIRA ticket, Confluence page, or incident report.

---

## Features

- **Plain English to KQL** — describe suspicious behavior, get a production-ready query
- **PDF import** — drag-and-drop incident reports; IOCs and behaviors extracted automatically
- **AI provider agnostic** — works with Claude, ChatGPT, Gemini, Copilot, Perplexity
- **25+ built-in examples** — categorized as Insider, Exfil, and General threat hunting scenarios
- **MITRE ATT&CK mapping** — every query tagged with relevant technique IDs and tactics
- **CMU CERT categorization** — insider threat queries tagged as IP Theft, IT Sabotage, Fraud, or Espionage
- **KQL syntax highlighting** — color-coded output for keywords, functions, operators, strings
- **Table selector** — target specific Sentinel or MDE tables, or let the AI choose
- **Time range selector** — 1d, 7d, 14d, 30d, 90d sliding windows
- **Severity selector** — High, Medium, Low, Informational, or auto
- **False positives panel** — AI-generated list of expected benign triggers per query
- **Response actions panel** — concrete next steps after a hunt fires
- **Hunting tips panel** — tuning and follow-on investigation guidance
- **Export to Markdown** — download a complete hunting package as `.md`
- **Copy to clipboard** — one-click copy for the prompt or the KQL query
- **Zero dependencies** — single HTML file, runs offline

---

## Supported Sentinel / MDE Tables

| Table | Source | Use Case |
|-------|--------|----------|
| `SecurityEvent` | Windows Security log (MMA/AMA) | Process execution, logon events |
| `DeviceProcessEvents` | MDE | Endpoint process behavior |
| `DeviceNetworkEvents` | MDE | Network connections from endpoints |
| `DeviceFileEvents` | MDE | File creation, modification, deletion |
| `DeviceRegistryEvents` | MDE | Registry key changes |
| `DeviceEvents` | MDE | USB, clipboard, other device events |
| `SigninLogs` | Azure AD | Authentication events |
| `AuditLogs` | Azure AD | Directory and resource changes |
| `OfficeActivity` | Microsoft 365 | SharePoint, OneDrive, Exchange |
| `CloudAppEvents` | Defender for Cloud Apps | SaaS app activity |
| `AzureActivity` | Azure Control Plane | Resource management actions |
| `Syslog` | Linux (MMA/AMA) | Linux system events |
| `CommonSecurityLog` | CEF sources | Firewall, proxy, network appliances |

---

## Built-In Example Scenarios

### Insider Threat (CMU CERT Framework)

| Category | Scenario |
|----------|----------|
| IP Theft | Mass bulk download from SharePoint/OneDrive before termination |
| IP Theft | Email forwarding to personal address via Outlook rules |
| IP Theft | Large file upload to personal cloud storage (Dropbox, Google Drive) |
| IP Theft | Sensitive file access outside user's department scope |
| IT Sabotage | Mass file/SharePoint deletion before or after account deactivation |
| IT Sabotage | Privileged user disabling security controls or audit logging |
| IT Sabotage | Database bulk delete/truncate by non-DBA account |
| Fraud | After-hours access to HR/payroll/financial systems |
| Fraud | Impossible travel — two logins from geographically impossible locations |
| Fraud | User accessing a terminated colleague's account |

### Exfiltration / Staging

| Scenario |
|----------|
| USB storage connected followed by large file copy |
| Data staged in temp folder then archived with 7-Zip/WinRAR |
| DNS exfiltration via unusually long subdomains or high-volume TXT queries |
| Sensitive keyword search across SharePoint/OneDrive |

### General Threat Hunting

| Scenario |
|----------|
| PowerShell downloading and executing a file from the internet |
| Brute force against Azure AD accounts |
| Lateral movement via PsExec or WMI |
| Ransomware deleting shadow copies (vssadmin) |
| Kerberoasting — SPN enumeration and TGS ticket requests |
| LSASS memory dumping via procdump or Task Manager |
| Pass-the-hash / pass-the-ticket authentication anomalies |
| Office macro spawning suspicious child processes |

---

## Usage

### Prerequisites

None. Open `index.html` in any modern browser.

### Workflow

**1. (Optional) Import a PDF**

Drag and drop an incident report, threat intel PDF, or alert export onto the import zone. The tool extracts IOCs and behaviors and pre-fills the hunt description.

**2. Describe the behavior**

Type or paste a plain-English description of what you want to hunt for. Use the quick-example pills for common scenarios. Adjust the table hint, time range, and severity selectors.

**3. Build the prompt**

Click **Build Prompt** (or press `Ctrl+Enter` / `Cmd+Enter`). The tool assembles a structured system prompt with your description and parameters.

**4. Get the KQL**

Copy the generated prompt. Open your AI of choice (use the provider selector to open it in a new tab). Paste the prompt into a new conversation. Copy the entire JSON response the AI returns.

**5. Render the results**

Paste the AI's JSON response into the **Paste AI Response** box. Click **Render Results**. The tool parses the JSON and displays:
- The formatted KQL query with syntax highlighting
- MITRE ATT&CK technique cards
- Hunt analysis (what/how/why)
- False positives, response actions, and hunting tips

**6. Export**

Click **Download .md** to save the full hunting package as a Markdown file, or **Copy Markdown** to paste it into a ticket or document.

---

## Companion Document

`insider-threat-hunting-library.md` is a standalone reference document included in this repository. It contains:

- The full master KQL generation prompt (for use without the web app)
- A categorized library of 25+ insider threat hunting scenarios covering IP theft, IT sabotage, fraud, espionage, and unintentional insider threat
- MITRE ATT&CK technique mappings per scenario
- Quick reference table of recommended Sentinel tables per behavior type
- Instructions for running queries in Log Analytics and Defender Advanced Hunting

Use this document independently with any AI assistant, or as a reference when building manual queries.

---

## Security & Data Handling

- **No data is transmitted from this page.** All processing is client-side.
- The PDF parser runs entirely in the browser — no file contents leave the machine.
- When a prompt is copied and pasted into an external AI provider, standard data-handling policies for that provider apply.
- A persistent banner in the UI reminds analysts not to paste sensitive or regulated data into external AI services without organizational approval.
- No API keys, credentials, or session tokens are stored or transmitted by this tool.

---

## File Structure

```
kql-hunt-gen/
├── index.html                        ← Complete application (single file)
└── insider-threat-hunting-library.md ← Standalone prompt library reference
```

---

## Limitations

- Query quality depends on the AI model used. Always review generated KQL before running in production.
- Queries are hunting queries, not detection rules. Validate against your environment's baseline before promoting to scheduled analytics.
- Table names and field mappings assume Microsoft-native data sources. Third-party SIEM or EDR products will require adaptation.
- The PDF parser extracts text only — scanned/image-based PDFs without embedded text will not parse correctly.
- The tool does not validate that generated KQL is syntactically correct; use the Sentinel query editor's validation before executing.
