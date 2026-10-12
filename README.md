


<img width="2157" height="1423" alt="Screenshot 2026-07-14 133652" src="https://github.com/user-attachments/assets/0a820c26-d37e-42ec-8570-f80bea7c7dc1" />



# 🛡️ Threat Hunt Report – Just Another Day

---

## 📌 Executive Summary

On 11 March 2026, a routine posture review of the Nimbus Health billing analyst account j.morris revealed a confirmed external account compromise, with Microsoft Sentinel and Defender telemetry showing valid credentials used over RDP from a public IP address to access the billing workstation and pivot to the organization's file server using native Windows tools. The attacker accessed sensitive data beyond the user's normal responsibilities, including approved invoices, a modified audit-trail file, and payroll and employee awards records, indicating deliberate cross-department data collection. The absence of malware or exploit activity, combined with the external RDP source, confirms the incident was a valid account compromise MITRE ATT&CK T1078 rather than malware infection or insider error.

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and network telemetry  
- Correlate attacker behavior to MITRE ATT&CK techniques  
- Document evidence, detection gaps, and response opportunities  

---

## 🧭 Scope & Environment

- **Environment:** <Placeholder>  
- **Data Sources:** Microsoft Sentinel / Microsoft Defender for Endpoint (MDE)
- **Timeframe:** 2026-03-08 → 2026-03-18  

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
  - [🚩 Flag 1](#-flag-1)
  - [🚩 Flag 2](#-flag-2)
  - [🚩 Flag 3](#-flag-3)
  - [🚩 Flag 4](#-flag-4)
  - [🚩 Flag 5](#-flag-5)
  - [🚩 Flag 6](#-flag-6)
  - [🚩 Flag 7](#-flag-7)
  - [🚩 Flag 8](#-flag-8)
  - [🚩 Flag 9](#-flag-9)
  - [🚩 Flag 10](#-flag-10)
  - [🚩 Flag 11](#-flag-11)
  - [🚩 Flag 12](#-flag-12)
  - [🚩 Flag 13](#-flag-13)
  - [🚩 Flag 14](#-flag-14)
  - [🚩 Flag 15](#-flag-15)
  - [🚩 Flag 16](#-flag-16)
  - [🚩 Flag 17](#-flag-17)
  - [🚩 Flag 18](#-flag-18)
  - [🚩 Flag 19](#-flag-19)
  - [🚩 Flag 20](#-flag-20)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

This hunt documents a full intrusion lifecycle on the Nimbus Health Windows estate, beginning with valid account abuse and external remote access, progressing through network reconnaissance and lateral movement to a file server, and concluding with cross-departmental data collection that reached beyond the compromised account's authorized role. 

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | Initail Access-Remote Access source | T1078 | High |
| 2 | Initial Access-Compromised User Account | T1021 | High |
| 3 | Initial Access-External Source Validation | T1078 | High |
| 4 |  Triage-Ruling Out Benign | N/A | Low |
| 5 | Discovery | T1033 | Medium |
| 6 | Discovery-Target Selection | T1018 | Medium |
| 7 | Discovery-Domain-Wide Enumeration | T1087 | Medium |
| 8 | Discovery-Local Network Mapping Preceding Pivot | T1016, T1018 | Medium |
| 9 | Collection-Reaching beyond | T1009 | High |
| 10 | Collection-Data Reaching Beyond | T1005 | Medium |
| 11 | Collection/Defense Evasion-Audit Trail Tampering | T1005 | High |
| 12 | Collection/Staging-Disguised File Movement | T1074,T1005 | High |
| 13 | Collecton-Scope Expansion | T1005 | Medium |
| 14 | Lateral Movement-Onward Hops | T1021.001 | High |
| 15 | Lateral Movement Triage-Ruling Out a Dead-End Host | T1021.001 | Low |
| 16 | Discovery-Privilege Enumeration| T1069,T1033 | Medium |
| 17 | Discovery-Share Enumeration | T1135 | Medium |
| 18 | Collecton-Cross Employee Data Access | T1005 | High |
| 19 | Collection-Scope Summary | T1005 | Medium |
| 20 |Judgement-Root Cause | T1078 | High |

---

## 🔍 Flag Analysis

_All flags below are collapsible for readability._

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: <Technique Name></strong></summary>

### 🎯 Objective
Determine whether the account's remote sessions originated from a legitimate internal source or an external one.

### 📌 Finding
The account's successful RDP session originated from a public, non-internal IP address, not from inside the clinic's network.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-bill-01.corp.nimbushealth.com |
| Timestamp | 2026-03-09 01:14:57 UTC |
| Logon Type | Remote Interactive |
| Account | j.morrison |
| Remote IP | 193.36.225.245 |

### 💡 Why it matters
A Remote Interactive (RDP) session is a full, interactive desktop session not a background or file-share connection. Combined with an external IP, this rules out normal on-site clinic work and establishes the true entry vector for the intrusion.
### 🔧 KQL Query Used
<Add KQL here>

### Query Used
```
DeviceProcessEvents
| where Timestamp between (datetime(2026-03-08)..datetime(2026-03-18))
| where DeviceName == "nh-wks-bill-01.corp.nimbushealth.com"
| summarize Processes=count() by AccountName
| order by Processes desc
```
📌 *Answer:* `j.morris`

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-2">🚩 <strong>Flag 2: <Technique Name></strong></summary>

### 🎯 Objective
Identify which account is driving the suspicious remote sessions.

### 📌 Finding
The account behind the anomalous RDP activity is j.morris, a billing submissions analyst.
### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-bill-01.corp.nimbushealth.com |
| Timestamp | 2026-03-09 01:14:57 UTC |
| Account Name | j.morris |
|Logon Type | Remote Interactive |
| Remote IP | 193.36.225.245 |

### 💡 Why it matters
Naming the account establishes the identity being abused throughout the entire intrusion chain. Every subsequent flag traces back to this one credential — confirming this is a valid-account compromise (T1078), not a rogue or unknown identity.

### 🔧 KQL Query Used
<Add KQL here>

```
### DeviceLogonEvents
| where Timestamp between (datetime(2026-03-08)..datetime(2026-03-18 23:59:59))
| where DeviceName startswith "nh-" and DeviceName contains "bill"
| where AccountName == "j.morris"
| where ActionType == "LogonSuccess"
| summarize Count=count() by LogonType
```
📌 *Answer:* `RemoteInteractive`

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-3">🚩 <strong>Flag 3: <Technique Name></strong></summary>

### 🎯 Objective
Confirm the remote session source is genuinely external and not a misread internal address.

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-bill-01.corp.nimbushealth.com |
| Timestamp | 2026-03-09 01:14:57 UTC |
| Account  | j.morrison |
|Logon Type | Network |
| Remote IP | 193.36.225.245 |

### 💡 Why it matters
This validation step removes any doubt that the session could be an employee VPN'd in from home or a misconfigured internal address. It's the evidence that anchors the "external compromise, not insider" conclusion for the rest of the hunt.

### 🔧 KQL Query Used
<Add KQL here>

```
### DeviceLogonEvents
| where Timestamp between (datetime(2026-03-08)..datetime(2026-03-18 23:59:59))
| where DeviceName startswith "nh-"
| where DeviceName contains "bill"
| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP
| order by Timestamp asc
```
📌 *Answer:* `193.36.225.245`

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-4">🚩 <strong>Flag 4: <Technique Name></strong></summary>

### 🎯 Objective
Determine whether the first chronological event in the account's activity — a burst of deletions — is attacker behavior or routine noise.

### 📌 Finding
The early deletion burst is routine application self-maintenance, not attacker anti-forensics.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-bill-01.corp.nimbushealth.com |
| Timestamp | Early in account timeline |
| Action Type | FileDeleted |
| Initiating Process | Application/system process |
| Path Pattern | Cache/temp paths, not staging directories |

### 💡 Why it matters
Treating this noise as signal would have sent the investigation down a false lead before the real intrusion activity even started. Validating "what's not the intruder" is as important as finding what is.

### 🔧 KQL Query Used
<Add KQL here>

```
### DeviceProcessEvents
| where Timestamp between (datetime(2026-03-08)..datetime(2026-03-18))
| where DeviceName == "nh-wks-bill-01.corp.nimbushealth.com"
| where AccountName == "j.morris"
| where ProcessCommandLine has_any ("del ", "erase", "rmdir", "rd ")
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```
📌 *Answer:* `Routine application cleanup (noise, not the intruder). The paths look like an application maintaining itself.`

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-5">🚩 <strong>Flag 5: <Technique Name></strong></summary>

### 🎯 Objective
Identify the first hands-on-keyboard commands run by the account to orient itself after landing.

### 📌 Finding
A deliberate five-command burst (whoami, hostname, net use, net view, net view \\NH-FS-01) was run in quick succession.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-bill-01.corp.nimbushealth.com |
| Timestamp | 2026-03-11 12:43–12:45 |
| Process | net.exe / whoami.exe / hostname.exe |
| Parent Process | cmd.exe |
| Command Line | whoami, hostname, net use, net view, net view \NH-FS-01 |

### 💡 Why it matters
This burst is the attacker's first situational-awareness pass confirming identity, host, and nearby network resources. It marks the transition from "just logged in" to "actively operating."

### 🔧 KQL Query Used
<Add KQL here>

```
### DeviceProcessEvents
| where Timestamp between (datetime(2026-03-11 12:42:00)..datetime(2026-03-11 12:45:00))
| where DeviceName == "nh-wks-bill-01.corp.nimbushealth.com"
| where AccountName == "j.morris"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```
📌 *Answer:* `whoami, hostname, net  use, net  view, net  view \\NH-FS-01`

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-6">🚩 <strong>Flag 6: <Technique Name></strong></summary>

### 🎯 Objective
Identify which specific host the final discovery command in the burst targeted.

### 📌 Finding
The final command explicitly targets NH-FS-01, the central file server holding department shares.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-bill-01.corp.nimbushealth.com |
| Timestamp | 2026-03-11 12:44:39 |
| Process | net.exe |
| Parent Process | cmd.exe |
| Command Line | net view \NH-FS-01 |

### 💡 Why it matters
Targeting a specific, named host — rather than sweeping the whole network — shows the attacker had already identified their next objective. This is deliberate target selection, not random probing.

### 🔧 KQL Query Used
<Add KQL here>

```
### DeviceProcessEvents
| where Timestamp between (datetime(2026-03-11 12:42:00)..datetime(2026-03-11 12:45:00))
| where DeviceName == "nh-wks-bill-01.corp.nimbushealth.com"
| where AccountName == "j.morris"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```
📌 *Answer:* `NH-FS-01`

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-7">🚩 <strong>Flag 7: <Technique Name></strong></summary>

### 🎯 Objective
Identify the command used to expand reconnaissance from the local subnet to the entire domain.

### 📌 Finding
The account ran net.exe view /domain:nimbus, enumerating every host registered in the domain.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-bill-01.corp.nimbushealth.com |
| Timestamp | 2026-03-11 13:17:35 |
| Process | net.exe |
| Parent Process | cmd.exe |
| Command Line | "net.exe" view /domain:nimbus |

### 💡 Why it matters
Recon scaled from one subnet to everything registered in the domain.

### 🔧 KQL Query Used
<Add KQL here>

```
### DeviceProcessEvents
| where Timestamp between (datetime(2026-03-11 13:16:00)..datetime(2026-03-11 13:20:00))
| where DeviceName == "nh-wks-bill-01.corp.nimbushealth.com"
| where AccountName == "j.morris"
| where FileName =~ "net.exe"
| project Timestamp, ProcessCommandLine
| order by Timestamp asc
```
📌 *Answer:* `"net.exe" view /domain:nimbus`

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-8">🚩 <strong>Flag 8: <Technique Name></strong></summary>

### 🎯 Objective
Determine what the account did in the two minutes immediately preceding its pivot to another host.

### 📌 Finding
They read the ARP table, then resolved addresses across 10.1.0.x with nslookup, finding the file server. They pivoted to a new host at 13:27.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-bill-01.corp.nimbushealth.com |
| Timestamp |13:18–13:20	arp -a, then a series of nslookup commands|
| Result | 10.1.0.x range resolved, including NH-FS-01 |
| 13:27 | Hop to another host |

### 💡 Why it matters
The recon was preparation for lateral movement, not idle curiosity.

### 🔧 KQL Query Used
<Add KQL here>

```
### DeviceProcessEvents
| where Timestamp between (datetime(2026-03-11 13:18:00)..datetime(2026-03-11 13:28:00))
| where DeviceName == "nh-wks-bill-01.corp.nimbushealth.com"
| where AccountName == "j.morris"
| where FileName in~ ("arp.exe", "nslookup.exe")
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```
📌 *Answer:* `Mapped the local subnet (arp -a plus an nslookup sweep of 10.1.0.x), then pivoted to the file server.`

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-9">🚩 <strong>Flag 9: <Technique Name></strong></summary>

### 🎯 Objective
Identify the billing workflow folder outside a submissions analyst’s role.

### 📌 Finding
The account reached into Approved, the sign-off stage downstream of where it belongs.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-fs-01.corp.nimbushealth.com |
| Account | j.morris |
| Expected stage | Submission / Pending |
| Folder | C:\Shares\Billing\2026-03\Approved |

### 💡 Why it matters
This is the first clear evidence of activity in a workflow stage the role should never touch.

### 🔧 KQL Query Used
<Add KQL here>

```
### DeviceFileEvents
| where Timestamp between (datetime(2026-03-08)..datetime(2026-03-18))
| where DeviceName startswith "nh-"
| where FolderPath contains @"\Shares\Billing"
| summarize Events=count() by FolderPath, InitiatingProcessAccountName
| order by Events desc
```
📌 *Answer:* `Approved`

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-10">🚩 <strong>Flag 10: <Technique Name></strong></summary>

### 🎯 Objective
Identify the invoice handled inside the approval folder.

### 📌 Finding
approved_pending_invoice_INV-664215_20260310.txt, which had already cleared sign-off.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-fs-01.corp.nimbushealth.com |
| Timestamp | 2026-03-10 12:09:49 UTC |
| Action Type | FileCreated (initiated by system) |
| Path | C:\Shares\Billing\2026-03\Approved\approved_pending_invoice_INV-664215_20260310.tx |

### 💡 Why it matters
It confirms data in a stage outside the role’s remit was in play.

### 🔧 KQL Query Used

```
 DeviceFileEvents
| where Timestamp between (datetime(2026-03-08)..datetime(2026-03-18))
| where DeviceName startswith "nh-"
| where FileName contains "pending_invoice"
    or FileName contains "approved_pending_invoice"
    or FileName contains "INV-"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessAccountName
| order by Timestamp asc
```
📌 *Answer:* `approved_pending_invoice_INV-664215_20260310.txt`

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-11">🚩 <strong>Flag 11: <Technique Name></strong></summary>

### 🎯 Objective
Identify the audit file modified.
### 📌 Finding
review_audit_20260311.txt, a record meant to reflect the reviewer’s actions, not a submitter’s.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-fs-01.corp.nimbushealth.com |
| Timestamp | 2026-03-11 13:08:17 UTC |
| Action Type | FileModified |
| Initiating Account | system |
| Path | C:\Shares\Billing\2026-03\AuditTrail\review_audit_20260311.txt |

### 💡 Why it matters
Altering the oversight record undermines the mechanism built to catch this misuse.

### 🔧 KQL Query Used
<Add KQL here>

```
 DeviceFileEvents
| where Timestamp between (datetime(2026-03-11T12:50:00Z)..datetime(2026-03-11T13:10:00Z))
| where DeviceName startswith "nh-"
| where ActionType == "FileModified"
| project Timestamp, FileName, FolderPath, InitiatingProcessAccountName, DeviceName
| order by Timestamp asc
```
📌 *Answer:* `review_audit_20260311.txt`
   
### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-12">🚩 <strong>Flag 12: <Technique Name></strong></summary>

### 🎯 Objective
Identify the payroll file as it ended up in the billing folder.
### 📌 Finding
A payroll file was renamed to look like a billing exception. The leftover double .txt.txt extension gives it away.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-fs-01  |
| Timestamp | 2026-03-11 13:02:01 UTC |
| Action Type | FIleRenamed |
| Previous Name | temp_payroll_review_jmorris_20260311.txt.txt |
| New Name | payroll_exception_reference_20260311.txt.txt |
|Destination | Billing\2026-03\Exceptions |

### 💡 Why it matters
This is the clearest evidence of deliberate staging: payroll data hidden in a share where it would not raise an eyebrow.

### 🔧 KQL Query Used
<Add KQL here>

```
 DeviceFileEvents
| where Timestamp between (datetime(2026-03-08)..datetime(2026-03-18))
| where DeviceName startswith "nh-"
| where FileName endswith ".txt.txt"
| project Timestamp, ActionType, FileName, PreviousFileName, FolderPath, InitiatingProcessAccountName, DeviceName
| order by Timestamp asc
```
📌 *Answer:* `payroll_exception_reference_20260311.txt.txt`

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-13">🚩 <strong>Flag 13: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-fs-01.corp.nimbushealth.com |
| Timestamp | 2026-03-11 13:00:24 UTC |
| Action Type | FileModified |
| Path | C:\Shares\HR\2026-03\Awards\quarterly_awards_shortlist_20260310.txt |

### 💡 Why it matters
It widens the activity from one payroll grab to a sweep of HR content.

### 🔧 KQL Query Used
<Add KQL here>

```
 DeviceFileEvents
| where Timestamp between (datetime(2026-03-11T12:55:00Z)..datetime(2026-03-11T13:05:00Z))
| where DeviceName startswith "nh-"
| where FolderPath contains @"HR\2026-03\Awards"
| project Timestamp, ActionType, FileName, PreviousFileName, FolderPath, InitiatingProcessAccountName, DeviceName
| order by Timestamp asc
```
📌 *Answer:* `quarterly_awards_shortlist_20260310.txt`

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-14">🚩 <strong>Flag 14: <Technique Name></strong></summary>

### 🎯 Objective
Name the two machines reached from the billing workstation.

### 📌 Finding
Remote sessions were opened onto the IT workstation and the file server, sourced from the billing workstation’s internal IP.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Source IP | 10.1.0.207 (billing workstation) |
| Timestamp | 13:27:05 UTC	nh-wks-it-01.corp.nimbushealth.com |
| Timestamp | 13:36:50 UTC	nh-fs-01.corp.nimbushealth.com (two rows) |
| Account | j.morris |

### 💡 Why it matters
Pivoting from an internal address confirms lateral movement from a compromised launch point.

### 🔧 KQL Query Used
<Add KQL here>

```
DeviceLogonEvents
| where Timestamp between (datetime(2026-03-08)..datetime(2026-03-18))
| where DeviceName startswith "nh-"
| where LogonType contains "Remote"
| where RemoteIP == "10.1.0.207"
| project Timestamp, AccountName, DeviceName, RemoteIP, LogonType
| order by Timestamp asc
```
📌 *Answer:* `nh-wks-it-01.corp.nimbushealth.com, nh-fs-01.corp.nimbushealth.com`

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-15">🚩 <strong>Flag 15: <Technique Name></strong></summary>

### 🎯 Objective
Prove whether anything happened on the IT workstation.
### 📌 Finding
Only automatic Windows first-logon profile setup ran. The landing happened, the hands-on activity did not.
### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-wks-it-01.corp.nimbushealth.com |
| Timestamp | Immediately after 13:27:05 |
| Process | Standard Windows first-logon processes only |
| Parent Process | userinit.exe / explorer.exe |
| Command Line | no attacker-run commands observed |

### 💡 Why it matters
Confirming an absence of activity is itself a finding it prevents wasted effort treating every touched host as equally compromised, and correctly redirects focus to the file server as the real second stage.
### 🔧 KQL Query Used
<Add KQL here>

```
DeviceProcessEvents
| where Timestamp between (datetime(2026-03-11 13:27:00)..datetime(2026-03-11 14:30:00))
| where DeviceName == "nh-wks-it-01.corp.nimbushealth.com"
| where AccountName == "j.morris"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```
📌 *Answer:* `IT workstation was only used for profile setup; no hands-on activity occurred.`

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-16">🚩 <strong>Flag 16: <Technique Name></strong></summary>

### 🎯 Objective
Identify the first command run on the file server after the account landed there.

### 📌 Finding
The account ran whoami /groups to check its privilege level and group memberships on the new host.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-fs-01.corp.nimbushealth.com |
| Timestamp | Immediately following 13:36:50 logon |
| Process |whoami.exe |
| Parent Process | cmd.exe |
| Command Line | whoami /groups |

### 💡 Why it matters
This is the attacker confirming what access their pivot actually bought them — a necessary step before deciding what to collect next on the new host.

### 🔧 KQL Query Used
<Add KQL here>

```
 DeviceProcessEvents
| where Timestamp between (datetime(2026-03-11 13:36:00)..datetime(2026-03-11 14:30:00))
| where DeviceName == "nh-fs-01.corp.nimbushealth.com"
| where AccountName == "j.morris"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```
📌 *Answer:* `whoami /groups`

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-17">🚩 <strong>Flag 17: <Technique Name></strong></summary>

### 🎯 Objective
Identify the command used to enumerate shares available on the file server.
### 📌 Finding
The account ran net share locally on the file server, listing every share it was exposing.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-fs-01.corp.nimbushealth.com |
| Timestamp | Immediately following whoami /groups |
| Process | net.exe |
| Parent Process | cmd.exe |
| Command Line | net share |

### 💡 Why it matters
This maps every available data source on the file server, directly setting up the targeted collection that follows payroll, HR, and billing records.

### 🔧 KQL Query Used
<Add KQL here>

```
 DeviceProcessEvents
| where Timestamp between (datetime(2026-03-11 13:36:00)..datetime(2026-03-11 14:30:00))
| where DeviceName == "nh-fs-01.corp.nimbushealth.com"
| where AccountName == "j.morris"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```
📌 *Answer:* `net share`

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-18">🚩 <strong>Flag 18: <Technique Name></strong></summary>

### 🎯 Objective
Identify the last file opened on the file server and whose it is.

### 📌 Finding
A payroll review belonging to d.patel, the approval-queue user, opened by the billing account.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | nh-fs-01.corp.nimbushealth.com |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
The collection crossed individual employee and department boundaries, increasing privacy impact.

### 🔧 KQL Query Used
<Add KQL here>

```
DeviceFileEvents
| where Timestamp between (datetime(2026-03-11 13:36:00)..datetime(2026-03-11 14:30:00))
| where DeviceName == "nh-fs-01.corp.nimbushealth.com"
| where FileName contains "payroll_review"
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessAccountName
| order by Timestamp asc
```
📌 *Answer:* `payroll_review_dpatel_20260311.txt (belongs to d.patel)`

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-19">🚩 <strong>Flag 19: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

```
DeviceFileEvents
| where Timestamp between (datetime(2026-03-11 12:50:00)..datetime(2026-03-11 14:30:00))
| where DeviceName startswith "nh-"
| where FolderPath contains @"\Shares\HR" or FileName contains "payroll"
| project Timestamp, ActionType, FileName, PreviousFileName, FolderPath, InitiatingProcessAccountName
| order by Timestamp asc
```
📌 *Answer:* `Broad HR data collection beyond payroll (multi-file HR collection: payroll and awards data.`


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-20">🚩 <strong>Flag 20: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
<Add KQL here>

```
 DeviceFileEvents
| where Timestamp between (datetime(2026-03-08)..datetime(2026-03-18))
| where DeviceName startswith "nh-"
| where ActionType == "FileCreated"
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".ps1"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
📌 *Answer:* `Compromised valid account used remotely from an external source; no malware or exploitation evidence.`


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

<!-- Duplicate Flag 1 section for Flags 2–20 -->

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- <Placeholder>
- <Placeholder>
- <Placeholder>

### Recommendations
- Contain and remediate the credential. Disable and reset j.morris, revoke active sessions, rotate any credentials reachable from the billing workstation and file server, and block 193.36.225.245. Treat the three hosts as in scope for review.
- Remove direct RDP exposure and enforce MFA. Close inbound RDP from the internet, require VPN or a gateway with MFA for all remote access, and enable Network Level Authentication and account lockout policies.
- Enforce least privilege and protect integrity of sensitive data. Restrict the billing role to the submissions and pending folders, lock the AuditTrail folder to reviewer and system accounts, and limit HR share access to HR staff. Alert on cross-share access and file renames into other departments’ folders.

---

## 🧾 Final Assessment

The Nimbus Health incident was an external compromise of a valid billing analyst account (j.morris), not an insider who forgot to hand back access and not a malware infection. The operator drove the account over RDP from a public IP (193.36.225.245) and used only native Windows tools (whoami, net, arp, nslookup). From the billing workstation they ran two recon bursts, mapped the local subnet, and pivoted by RDP to the file server (the IT workstation hop was a dead end with no hands-on activity). On the file server they reached into the approval stage, modified the audit trail, staged payroll material in the billing share under a disguised .txt.txt name, and collected HR files belonging to other employees (payroll and awards). No dropped binaries or exploitation were found, so the root cause is credential compromise (T1078), and the exposure includes payroll and HR data of employees outside the account holder’s scope.

---

## 📎 Analyst Notes

- Report structured for interview and portfolio review  
- Evidence reproducible via advanced hunting  
- Techniques mapped directly to MITRE ATT&CK  

---
