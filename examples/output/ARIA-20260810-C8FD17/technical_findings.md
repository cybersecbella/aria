# Technical Findings Report -- Test Run

**Case ID:** ARIA-20260810-C8FD17  
**Analyst of record:** Your Name  
**Case opened:** 2026-08-10T17:04:12.791246+00:00  
**Artifacts analyzed:** disk, memory, logs, pcap

## 1. Severity Summary

| Severity | Count |
|---|---|
| critical | 9 |
| high | 12 |
| medium | 7 |
| low | 0 |
| info | 0 |

## 2. Orchestration Trail

ARIA is agent-orchestrated: each tool below ran because the prior tool's findings warranted it, not because of a fixed pipeline order.

| # | Tool | Reason invoked | Findings produced |
|---|---|---|---|
| 1 | AutoTriage | Always runs first: cheapest signal source, decides what else is worth analyzing. | 6 |
| 2 | VolAI | Disk triage flagged malware/ransomware indicators requiring memory analysis. | 6 |
| 3 | IAM Auditor | Credential theft or identity signal detected upstream; auditing account abuse. | 6 |
| 4 | AI PCAP Analyst | Live beaconing observed in memory; confirming C2 on the wire. | 6 |
| 5 | AI Detection Engineer | All available evidence sources exhausted; correlating findings and drafting detections. | 4 |

<details><summary>Full orchestrator decision log</summary>

- Case ARIA-20260810-C8FD17 opened for Test Run with 4 artifact(s).
- [AutoTriage] malware/ransomware indicators on disk -> routing to VolAI for memory analysis.
- [orchestrator] routing to VolAI (priority 3); remaining candidates: ['IAM Auditor', 'AI PCAP Analyst']
- [VolAI] credential dumping confirmed in memory -> routing to IAM Auditor to check for downstream account abuse.
- [VolAI] live C2-style connection observed -> routing to AI PCAP Analyst to confirm on the wire.
- [orchestrator] routing to IAM Auditor (priority 3); remaining candidates: ['AI PCAP Analyst']
- [IAM Auditor] confirmed identity compromise / over-privileged access -> flagging for detection engineering once evidence collection completes.
- [orchestrator] routing to AI PCAP Analyst (priority 3); remaining candidates: []
- [AI PCAP Analyst] traffic analysis complete -> flagging for detection engineering.
- [orchestrator] no evidence-gathering tools remain -- routing to AI Detection Engineer for correlation and rule drafting.
- [AI Detection Engineer] correlated 24 raw findings into 4 attack-chain finding(s) and drafted 5 detection rule(s).

</details>

## 3. Detailed Findings

### [CRITICAL] Ransom note recovered

- **Source tool:** AutoTriage
- **Confidence:** 0.95
- **Timestamp:** 2026-08-04T11:03:10Z
- **ATT&CK techniques:** `T1486` (Data Encrypted for Impact), `T1490` (Inhibit System Recovery)
- **Evidence refs:** disk-01
- **Finding ID:** `autotriage-ransom-5`

All your files have been encrypted. Contact darkhollow_support@protonmail.com with your case ID.

### [CRITICAL] LSASS memory access consistent with credential dumping

- **Source tool:** VolAI
- **Confidence:** 0.9
- **ATT&CK techniques:** `T1003.001` (OS Credential Dumping: LSASS Memory)
- **Evidence refs:** mem-01
- **Finding ID:** `volai-lsass-4`

Consistent with credential dumping (Mimikatz-style handle access)

### [CRITICAL] C2 traffic confirmed: 10.20.4.117 -> 185.220.101.47:443

- **Source tool:** AI PCAP Analyst
- **Confidence:** 0.9
- **ATT&CK techniques:** `T1071.001` (Application Layer Protocol: Web Protocols), `T1568` (Dynamic Resolution)
- **IOCs:** 185.220.101.47
- **Evidence refs:** pcap-01
- **Finding ID:** `pcap-c2-1`

TLS to a domain registered 9 days ago; JA3 matches known C2 framework fingerprint

### [CRITICAL] C2 traffic confirmed: 10.20.4.117 -> 185.220.101.47:443

- **Source tool:** AI PCAP Analyst
- **Confidence:** 0.9
- **ATT&CK techniques:** `T1071.001` (Application Layer Protocol: Web Protocols), `T1568` (Dynamic Resolution)
- **IOCs:** 185.220.101.47
- **Evidence refs:** pcap-01
- **Finding ID:** `pcap-c2-2`

Periodic ~60s beacon interval, low jitter -- consistent with C2 heartbeat

### [CRITICAL] Correlated attack chain: phishing dropper -> credential theft

- **Source tool:** AI Detection Engineer
- **Confidence:** 0.9
- **ATT&CK techniques:** `T1204.002` (User Execution: Malicious File), `T1003.001` (OS Credential Dumping: LSASS Memory)
- **Finding ID:** `det-corr-1`

AutoTriage identified a masqueraded binary dropped by a macro-enabled attachment; VolAI independently confirmed LSASS credential access from a process in the same execution chain. High-confidence single incident, not two unrelated events.

### [CRITICAL] Correlated attack chain: memory-resident implant confirmed communicating with C2

- **Source tool:** AI Detection Engineer
- **Confidence:** 0.9
- **ATT&CK techniques:** `T1071.001` (Application Layer Protocol: Web Protocols), `T1568` (Dynamic Resolution)
- **Finding ID:** `det-corr-3`

The network connection observed live in memory by VolAI matches a JA3-fingerprinted TLS session to a newly-registered domain captured by the PCAP Analyst, confirming active command-and-control rather than benign traffic.

### [CRITICAL] Correlated attack chain: shadow-copy deletion preceding mass file encryption

- **Source tool:** AI Detection Engineer
- **Confidence:** 0.9
- **ATT&CK techniques:** `T1490` (Inhibit System Recovery), `T1486` (Data Encrypted for Impact), `T1021.002` (Remote Services: SMB/Windows Admin Shares)
- **Finding ID:** `det-corr-4`

A shadow-copy deletion command was logged shortly before abnormal SMB volume and mass file-rename activity on the finance share, and encrypted files plus a ransom note were recovered from disk -- consistent with ransomware deployment following data staging.

### [CRITICAL] Impossible travel sign-in for jmartin@northshoreclinic.org

- **Source tool:** IAM Auditor
- **Confidence:** 0.85
- **Timestamp:** 2026-08-04T10:05:44Z
- **ATT&CK techniques:** `T1078.004` (Valid Accounts: Cloud Accounts)
- **Evidence refs:** logs-01
- **Finding ID:** `iam-travel-3`

Sign-in from Amsterdam, NL 11 minutes after sign-in from Chicago, US (impossible travel)

### [CRITICAL] Correlated attack chain: stolen credentials used for lateral movement

- **Source tool:** AI Detection Engineer
- **Confidence:** 0.85
- **ATT&CK techniques:** `T1003.001` (OS Credential Dumping: LSASS Memory), `T1078.004` (Valid Accounts: Cloud Accounts), `T1021` (Remote Services)
- **Finding ID:** `det-corr-2`

Credentials harvested in memory were used minutes later for an anomalous privileged service-account logon and an impossible-travel sign-in, indicating the stolen material was actively used, not just collected.

### [HIGH] Suspicious file: C:\Windows\Temp\svch0st.exe

- **Source tool:** AutoTriage
- **Confidence:** 0.8
- **ATT&CK techniques:** `T1204.002` (User Execution: Malicious File), `T1036.005` (Masquerading: Match Legitimate Name or Location)
- **IOCs:** 2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b
- **Evidence refs:** disk-01
- **Finding ID:** `autotriage-file-2`

Masquerading as svchost.exe, unsigned, dropped by macro

### [HIGH] Suspicious process: svch0st.exe (pid 4412)

- **Source tool:** VolAI
- **Confidence:** 0.8
- **ATT&CK techniques:** `T1059.001` (Command and Scripting Interpreter: PowerShell)
- **Evidence refs:** mem-01
- **Finding ID:** `volai-proc-1`

Office spawning an unsigned binary from Temp

### [HIGH] Suspicious process: powershell.exe (pid 4488)

- **Source tool:** VolAI
- **Confidence:** 0.8
- **ATT&CK techniques:** `T1059.001` (Command and Scripting Interpreter: PowerShell)
- **Evidence refs:** mem-01
- **Finding ID:** `volai-proc-2`

Encoded PowerShell launched by malware dropper

### [HIGH] Suspicious process: rundll32.exe (pid 4501)

- **Source tool:** VolAI
- **Confidence:** 0.8
- **ATT&CK techniques:** `T1059.001` (Command and Scripting Interpreter: PowerShell)
- **Evidence refs:** mem-01
- **Finding ID:** `volai-proc-3`

LSASS credential access module

### [HIGH] Malicious inbox rule created by svc_backup

- **Source tool:** IAM Auditor
- **Confidence:** 0.8
- **Timestamp:** 2026-08-04T10:31:19Z
- **ATT&CK techniques:** `T1114.003` (Email Collection: Email Forwarding Rule), `T1564.008` (Hide Artifacts: Email Hiding Rules)
- **Evidence refs:** logs-01
- **Finding ID:** `iam-mailrule-4`

New inbox rule created: forward all mail matching 'wire' to external address, then delete

### [HIGH] Timestomping detected: C:\Windows\Temp\svch0st.exe

- **Source tool:** AutoTriage
- **Confidence:** 0.75
- **ATT&CK techniques:** `T1070.006` (Indicator Removal: Timestomp)
- **Evidence refs:** disk-01
- **Finding ID:** `autotriage-timestomp-6`

Standard timestamps inconsistent with $FN timestamps

### [HIGH] Injected memory region in pid 4488

- **Source tool:** VolAI
- **Confidence:** 0.75
- **ATT&CK techniques:** `T1055` (Process Injection)
- **Evidence refs:** mem-01
- **Finding ID:** `volai-malfind-5`

Injected shellcode region, no backing file

### [HIGH] Over-privileged service account: svc_backup

- **Source tool:** IAM Auditor
- **Confidence:** 0.75
- **ATT&CK techniques:** `T1078.003` (Valid Accounts: Local Accounts)
- **Evidence refs:** logs-01
- **Finding ID:** `iam-overpriv-5`

Service account is a member of Domain Admins -- far broader than backup duties require

### [HIGH] Live connection from pid 4488 to 185.220.101.47:443

- **Source tool:** VolAI
- **Confidence:** 0.7
- **ATT&CK techniques:** `T1071.001` (Application Layer Protocol: Web Protocols)
- **IOCs:** 185.220.101.47
- **Evidence refs:** mem-01
- **Finding ID:** `volai-net-6`

Beaconing to unrecognized external IP over TLS

### [HIGH] Anomalous service-account logon: svc_backup

- **Source tool:** IAM Auditor
- **Confidence:** 0.7
- **Timestamp:** 2026-08-04T09:42:03Z
- **ATT&CK techniques:** `T1078.003` (Valid Accounts: Local Accounts)
- **Evidence refs:** logs-01
- **Finding ID:** `iam-anomlogon-1`

Interactive-style network logon using service account outside normal hours

### [HIGH] ET MALWARE Possible Cobalt-Strike-like JA3

- **Source tool:** AI PCAP Analyst
- **Confidence:** 0.7
- **ATT&CK techniques:** `T1071.001` (Application Layer Protocol: Web Protocols)
- **Evidence refs:** pcap-01
- **Finding ID:** `pcap-alert-5`

10.20.4.117 -> 185.220.101.47

### [HIGH] Abnormal SMB volume: 10.20.6.55 -> 10.20.6.71

- **Source tool:** AI PCAP Analyst
- **Confidence:** 0.65
- **ATT&CK techniques:** `T1021.002` (Remote Services: SMB/Windows Admin Shares), `T1486` (Data Encrypted for Impact)
- **Evidence refs:** pcap-01
- **Finding ID:** `pcap-smb-3`

Abnormal SMB volume between file server and backup host outside backup window

### [MEDIUM] ET POLICY TLS SNI for newly registered domain

- **Source tool:** AI PCAP Analyst
- **Confidence:** 0.7
- **ATT&CK techniques:** `T1071.001` (Application Layer Protocol: Web Protocols)
- **Evidence refs:** pcap-01
- **Finding ID:** `pcap-alert-6`

10.20.4.117 -> 185.220.101.47

### [MEDIUM] Sensitive privileges assigned to svc_backup

- **Source tool:** IAM Auditor
- **Confidence:** 0.6
- **Timestamp:** 2026-08-04T09:43:10Z
- **ATT&CK techniques:** `T1078` (Valid Accounts)
- **Evidence refs:** logs-01
- **Finding ID:** `iam-privesc-2`

Special privileges assigned: SeDebugPrivilege, SeBackupPrivilege

### [MEDIUM] Privileged account without MFA: svc_backup

- **Source tool:** IAM Auditor
- **Confidence:** 0.6
- **ATT&CK techniques:** `T1078` (Valid Accounts)
- **Evidence refs:** logs-01
- **Finding ID:** `iam-nomfa-6`

svc_backup is not enrolled in MFA and holds Domain Admins, Backup Operators access.

### [MEDIUM] DNS lookup for Tor gateway / onion domain

- **Source tool:** AI PCAP Analyst
- **Confidence:** 0.6
- **ATT&CK techniques:** `T1071.004` (Application Layer Protocol: DNS)
- **Evidence refs:** pcap-01
- **Finding ID:** `pcap-dns-4`

DNS lookups for onion gateway domain

### [MEDIUM] Suspicious file: C:\Users\jmartin\Downloads\Invoice_0847.xlsm

- **Source tool:** AutoTriage
- **Confidence:** 0.5
- **ATT&CK techniques:** `T1486` (Data Encrypted for Impact)
- **IOCs:** 1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a
- **Evidence refs:** disk-01
- **Finding ID:** `autotriage-file-1`

Macro-enabled spreadsheet, delivered via email attachment

### [MEDIUM] Suspicious file: C:\ProgramData\wintmp\mimidump.log

- **Source tool:** AutoTriage
- **Confidence:** 0.5
- **ATT&CK techniques:** `T1486` (Data Encrypted for Impact)
- **IOCs:** 3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f
- **Evidence refs:** disk-01
- **Finding ID:** `autotriage-file-3`

Credential dumper output artifact

### [MEDIUM] Suspicious file: C:\Users\jmartin\Documents\Finance\Q3_Projections.xlsx.locked

- **Source tool:** AutoTriage
- **Confidence:** 0.5
- **ATT&CK techniques:** `T1486` (Data Encrypted for Impact)
- **IOCs:** 4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e
- **Evidence refs:** disk-01
- **Finding ID:** `autotriage-file-4`

Encrypted by ransomware, extension appended

## 4. Incident Timeline

| Timestamp (UTC) | Event | Source |
|---|---|---|
| 2026-08-04T09:42:03Z | Anomalous service-account logon: svc_backup | IAM Auditor |
| 2026-08-04T09:43:10Z | Sensitive privileges assigned to svc_backup | IAM Auditor |
| 2026-08-04T10:05:44Z | Impossible travel sign-in for jmartin@northshoreclinic.org | IAM Auditor |
| 2026-08-04T10:31:19Z | Malicious inbox rule created by svc_backup | IAM Auditor |
| 2026-08-04T11:03:10Z | Ransom note recovered | AutoTriage |

## 5. Indicators of Compromise

- `185.220.101.47`
- `1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a`
- `2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b`
- `3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f`
- `4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e`

## 6. Drafted Detection Rules (Sigma-style)

Generated by the AI Detection Engineer node based on this incident's confirmed techniques. Review and tune thresholds before deploying to production.

### Suspicious LSASS Access by Non-Standard Process  
`aria-rule-lsass-access` -- level: **high**

```yaml
title: Suspicious LSASS Access by Non-Standard Process
id: aria-rule-lsass-access
level: high
logsource: {'category': 'process_access', 'product': 'windows'}
detection: {'selection': {'TargetImage|endswith': '\\lsass.exe', 'GrantedAccess': '0x1010'}, 'condition': 'selection'}
tags: ['T1003.001']
```

### Impossible Travel Sign-In for Privileged Identity  
`aria-rule-impossible-travel` -- level: **critical**

```yaml
title: Impossible Travel Sign-In for Privileged Identity
id: aria-rule-impossible-travel
level: critical
logsource: {'category': 'authentication', 'product': 'azuread'}
detection: {'selection': {'event': 'SigninLogs', 'travel_delta_minutes': '<60', 'distance_km': '>500'}, 'condition': 'selection'}
tags: ['T1078.004']
```

### Beaconing TLS Session to Newly Registered Domain  
`aria-rule-c2-beacon` -- level: **high**

```yaml
title: Beaconing TLS Session to Newly Registered Domain
id: aria-rule-c2-beacon
level: high
logsource: {'category': 'network_connection', 'product': 'zeek'}
detection: {'selection': {'domain_age_days': '<30', 'interval_jitter': '<5%'}, 'condition': 'selection'}
tags: ['T1071.001', 'T1568']
```

### Shadow Copy Deletion Followed by Mass File Rename  
`aria-rule-ransomware-staging` -- level: **critical**

```yaml
title: Shadow Copy Deletion Followed by Mass File Rename
id: aria-rule-ransomware-staging
level: critical
logsource: {'category': 'process_creation', 'product': 'windows'}
detection: {'selection': {'CommandLine|contains': 'vssadmin delete shadows'}, 'condition': 'selection'}
tags: ['T1490', 'T1486']
```

### Service Account Holding Domain Admin Membership  
`aria-rule-overprivileged-svc` -- level: **medium**

```yaml
title: Service Account Holding Domain Admin Membership
id: aria-rule-overprivileged-svc
level: medium
logsource: {'category': 'identity_posture', 'product': 'activedirectory'}
detection: {'selection': {'account_type': 'service', 'group_membership': 'Domain Admins'}, 'condition': 'selection'}
tags: ['T1078.003']
```

## 7. ATT&CK Coverage

See `attck_heatmap.html` and `attck_navigator_layer.json` in this report package.

- `T1486` -- Data Encrypted for Impact (impact) -- observed 6x
- `T1071.001` -- Application Layer Protocol: Web Protocols (command-and-control) -- observed 6x
- `T1059.001` -- Command and Scripting Interpreter: PowerShell (execution) -- observed 3x
- `T1003.001` -- OS Credential Dumping: LSASS Memory (credential-access) -- observed 3x
- `T1568` -- Dynamic Resolution (command-and-control) -- observed 3x
- `T1204.002` -- User Execution: Malicious File (execution) -- observed 2x
- `T1490` -- Inhibit System Recovery (impact) -- observed 2x
- `T1078.003` -- Valid Accounts: Local Accounts (privilege-escalation) -- observed 2x
- `T1078` -- Valid Accounts (defense-evasion) -- observed 2x
- `T1078.004` -- Valid Accounts: Cloud Accounts (defense-evasion) -- observed 2x
- `T1021.002` -- Remote Services: SMB/Windows Admin Shares (lateral-movement) -- observed 2x
- `T1036.005` -- Masquerading: Match Legitimate Name or Location (defense-evasion) -- observed 1x
- `T1070.006` -- Indicator Removal: Timestomp (defense-evasion) -- observed 1x
- `T1055` -- Process Injection (defense-evasion) -- observed 1x
- `T1114.003` -- Email Collection: Email Forwarding Rule (collection) -- observed 1x
- `T1564.008` -- Hide Artifacts: Email Hiding Rules (defense-evasion) -- observed 1x
- `T1071.004` -- Application Layer Protocol: DNS (command-and-control) -- observed 1x
- `T1021` -- Remote Services (lateral-movement) -- observed 1x