# Forensic Evidence Report -- Test Run

**Case ID:** ARIA-20260810-C8FD17  
**Examiner of record:** Your Name  
**Analysis system:** ARIA v0.1.0 (AI-assisted, examiner-reviewed)  
**Report generated:** 2026-08-10T17:04:12.791246+00:00

> **Notice.** This report was produced with AI-assisted analysis tools and is intended to support, not replace, examiner judgment and legal review. All findings below reference the specific evidence item and confidence level on which they rest. This document is a template exhibit and should be reviewed by counsel before production or testimony.

## 1. Evidence Inventory and Chain of Custody

| Artifact ID | Type | Path/Reference | SHA-256 | Collected | Description |
|---|---|---|---|---|---|
| disk-evidence | disk | `data\sample_incident\disk_manifest.json` | `unverified-in-demo-mode` | 2026-08-10T17:04:12.791246+00:00 | Disk artifact manifest provided at CLI invocation. |
| memory-evidence | memory | `data\sample_incident\memory_manifest.json` | `unverified-in-demo-mode` | 2026-08-10T17:04:12.791246+00:00 | Memory artifact manifest provided at CLI invocation. |
| logs-evidence | logs | `data\sample_incident\log_manifest.json` | `unverified-in-demo-mode` | 2026-08-10T17:04:12.791246+00:00 | Logs artifact manifest provided at CLI invocation. |
| pcap-evidence | pcap | `data\sample_incident\pcap_manifest.json` | `unverified-in-demo-mode` | 2026-08-10T17:04:12.791246+00:00 | Pcap artifact manifest provided at CLI invocation. |

All artifacts listed above were ingested read-only by ARIA's analysis tools. No modification was made to source evidence during automated analysis. Hash values should be independently verified against the original acquisition hash before this report is relied upon.

## 2. Methodology

ARIA performed an AI-orchestrated examination using the following analysis modules, invoked adaptively based on findings at each stage (full decision rationale in Section 5):

- **AutoTriage** -- invoked because: Always runs first: cheapest signal source, decides what else is worth analyzing.
- **VolAI** -- invoked because: Disk triage flagged malware/ransomware indicators requiring memory analysis.
- **IAM Auditor** -- invoked because: Credential theft or identity signal detected upstream; auditing account abuse.
- **AI PCAP Analyst** -- invoked because: Live beaconing observed in memory; confirming C2 on the wire.
- **AI Detection Engineer** -- invoked because: All available evidence sources exhausted; correlating findings and drafting detections.

## 3. Findings

Each finding below is stated with its supporting evidence reference and the examiner-tool's confidence score (0.0-1.0). Findings below a confidence of 0.6 are noted as such and should be independently corroborated before being relied upon in any legal proceeding.

**Finding 1.** Ransom note recovered.

- Observation: All your files have been encrypted. Contact darkhollow_support@protonmail.com with your case ID.
- Supporting evidence: disk-01
- Analysis confidence: 0.95
- Associated timestamp: 2026-08-04T11:03:10Z (source clock, not independently normalized to UTC unless noted)
- Analysis module: AutoTriage

**Finding 2.** LSASS memory access consistent with credential dumping.

- Observation: Consistent with credential dumping (Mimikatz-style handle access)
- Supporting evidence: mem-01
- Analysis confidence: 0.9
- Analysis module: VolAI

**Finding 3.** C2 traffic confirmed: 10.20.4.117 -> 185.220.101.47:443.

- Observation: TLS to a domain registered 9 days ago; JA3 matches known C2 framework fingerprint
- Supporting evidence: pcap-01
- Analysis confidence: 0.9
- Analysis module: AI PCAP Analyst

**Finding 4.** C2 traffic confirmed: 10.20.4.117 -> 185.220.101.47:443.

- Observation: Periodic ~60s beacon interval, low jitter -- consistent with C2 heartbeat
- Supporting evidence: pcap-01
- Analysis confidence: 0.9
- Analysis module: AI PCAP Analyst

**Finding 5.** Correlated attack chain: phishing dropper -> credential theft.

- Observation: AutoTriage identified a masqueraded binary dropped by a macro-enabled attachment; VolAI independently confirmed LSASS credential access from a process in the same execution chain. High-confidence single incident, not two unrelated events.
- Supporting evidence: not specified
- Analysis confidence: 0.9
- Analysis module: AI Detection Engineer

**Finding 6.** Correlated attack chain: memory-resident implant confirmed communicating with C2.

- Observation: The network connection observed live in memory by VolAI matches a JA3-fingerprinted TLS session to a newly-registered domain captured by the PCAP Analyst, confirming active command-and-control rather than benign traffic.
- Supporting evidence: not specified
- Analysis confidence: 0.9
- Analysis module: AI Detection Engineer

**Finding 7.** Correlated attack chain: shadow-copy deletion preceding mass file encryption.

- Observation: A shadow-copy deletion command was logged shortly before abnormal SMB volume and mass file-rename activity on the finance share, and encrypted files plus a ransom note were recovered from disk -- consistent with ransomware deployment following data staging.
- Supporting evidence: not specified
- Analysis confidence: 0.9
- Analysis module: AI Detection Engineer

**Finding 8.** Impossible travel sign-in for jmartin@northshoreclinic.org.

- Observation: Sign-in from Amsterdam, NL 11 minutes after sign-in from Chicago, US (impossible travel)
- Supporting evidence: logs-01
- Analysis confidence: 0.85
- Associated timestamp: 2026-08-04T10:05:44Z (source clock, not independently normalized to UTC unless noted)
- Analysis module: IAM Auditor

**Finding 9.** Correlated attack chain: stolen credentials used for lateral movement.

- Observation: Credentials harvested in memory were used minutes later for an anomalous privileged service-account logon and an impossible-travel sign-in, indicating the stolen material was actively used, not just collected.
- Supporting evidence: not specified
- Analysis confidence: 0.85
- Analysis module: AI Detection Engineer

**Finding 10.** Suspicious file: C:\Windows\Temp\svch0st.exe.

- Observation: Masquerading as svchost.exe, unsigned, dropped by macro
- Supporting evidence: disk-01
- Analysis confidence: 0.8
- Analysis module: AutoTriage

**Finding 11.** Suspicious process: svch0st.exe (pid 4412).

- Observation: Office spawning an unsigned binary from Temp
- Supporting evidence: mem-01
- Analysis confidence: 0.8
- Analysis module: VolAI

**Finding 12.** Suspicious process: powershell.exe (pid 4488).

- Observation: Encoded PowerShell launched by malware dropper
- Supporting evidence: mem-01
- Analysis confidence: 0.8
- Analysis module: VolAI

**Finding 13.** Suspicious process: rundll32.exe (pid 4501).

- Observation: LSASS credential access module
- Supporting evidence: mem-01
- Analysis confidence: 0.8
- Analysis module: VolAI

**Finding 14.** Malicious inbox rule created by svc_backup.

- Observation: New inbox rule created: forward all mail matching 'wire' to external address, then delete
- Supporting evidence: logs-01
- Analysis confidence: 0.8
- Associated timestamp: 2026-08-04T10:31:19Z (source clock, not independently normalized to UTC unless noted)
- Analysis module: IAM Auditor

**Finding 15.** Timestomping detected: C:\Windows\Temp\svch0st.exe.

- Observation: Standard timestamps inconsistent with $FN timestamps
- Supporting evidence: disk-01
- Analysis confidence: 0.75
- Analysis module: AutoTriage

**Finding 16.** Injected memory region in pid 4488.

- Observation: Injected shellcode region, no backing file
- Supporting evidence: mem-01
- Analysis confidence: 0.75
- Analysis module: VolAI

**Finding 17.** Over-privileged service account: svc_backup.

- Observation: Service account is a member of Domain Admins -- far broader than backup duties require
- Supporting evidence: logs-01
- Analysis confidence: 0.75
- Analysis module: IAM Auditor

**Finding 18.** Live connection from pid 4488 to 185.220.101.47:443.

- Observation: Beaconing to unrecognized external IP over TLS
- Supporting evidence: mem-01
- Analysis confidence: 0.7
- Analysis module: VolAI

**Finding 19.** Anomalous service-account logon: svc_backup.

- Observation: Interactive-style network logon using service account outside normal hours
- Supporting evidence: logs-01
- Analysis confidence: 0.7
- Associated timestamp: 2026-08-04T09:42:03Z (source clock, not independently normalized to UTC unless noted)
- Analysis module: IAM Auditor

**Finding 20.** ET MALWARE Possible Cobalt-Strike-like JA3.

- Observation: 10.20.4.117 -> 185.220.101.47
- Supporting evidence: pcap-01
- Analysis confidence: 0.7
- Analysis module: AI PCAP Analyst

**Finding 21.** Abnormal SMB volume: 10.20.6.55 -> 10.20.6.71.

- Observation: Abnormal SMB volume between file server and backup host outside backup window
- Supporting evidence: pcap-01
- Analysis confidence: 0.65
- Analysis module: AI PCAP Analyst

**Finding 22.** ET POLICY TLS SNI for newly registered domain.

- Observation: 10.20.4.117 -> 185.220.101.47
- Supporting evidence: pcap-01
- Analysis confidence: 0.7
- Analysis module: AI PCAP Analyst

**Finding 23.** Sensitive privileges assigned to svc_backup.

- Observation: Special privileges assigned: SeDebugPrivilege, SeBackupPrivilege
- Supporting evidence: logs-01
- Analysis confidence: 0.6
- Associated timestamp: 2026-08-04T09:43:10Z (source clock, not independently normalized to UTC unless noted)
- Analysis module: IAM Auditor

**Finding 24.** Privileged account without MFA: svc_backup.

- Observation: svc_backup is not enrolled in MFA and holds Domain Admins, Backup Operators access.
- Supporting evidence: logs-01
- Analysis confidence: 0.6
- Analysis module: IAM Auditor

**Finding 25.** DNS lookup for Tor gateway / onion domain.

- Observation: DNS lookups for onion gateway domain
- Supporting evidence: pcap-01
- Analysis confidence: 0.6
- Analysis module: AI PCAP Analyst

**Finding 26.** Suspicious file: C:\Users\jmartin\Downloads\Invoice_0847.xlsm. *(low confidence -- recommend independent corroboration)*

- Observation: Macro-enabled spreadsheet, delivered via email attachment
- Supporting evidence: disk-01
- Analysis confidence: 0.5
- Analysis module: AutoTriage

**Finding 27.** Suspicious file: C:\ProgramData\wintmp\mimidump.log. *(low confidence -- recommend independent corroboration)*

- Observation: Credential dumper output artifact
- Supporting evidence: disk-01
- Analysis confidence: 0.5
- Analysis module: AutoTriage

**Finding 28.** Suspicious file: C:\Users\jmartin\Documents\Finance\Q3_Projections.xlsx.locked. *(low confidence -- recommend independent corroboration)*

- Observation: Encrypted by ransomware, extension appended
- Supporting evidence: disk-01
- Analysis confidence: 0.5
- Analysis module: AutoTriage

## 4. Indicators of Compromise (for exhibit reference)

- `185.220.101.47`
- `1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a`
- `2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b`
- `3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f`
- `4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e`

## 5. Examiner Decision Log

The following is the complete, unedited decision trail produced by the analysis system, preserved for transparency and reproducibility:

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

## 6. Examiner Attestation

I, Your Name, reviewed the automated findings above against the source evidence and attest to their accuracy as of the date of this report, subject to the caveats noted herein. Signature: ________________________  Date: ________________