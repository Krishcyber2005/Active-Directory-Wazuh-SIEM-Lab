# Active Directory & Wazuh SIEM Cybersecurity Lab

This repository contains my hands-on **Active Directory & SIEM capstone project**, where I built a small enterprise environment, executed real attacks (brute force, Kerberoasting, persistence, etc.), and detected them using **Wazuh SIEM + Sysmon**.

📄 **Full report (PDF):**  
[Active Directory & Wazuh SIEM Capstone Report](./Active-Directory-Wazuh-SIEM-Capstone.pdf)

---

## 🏗 Lab Architecture

The lab simulates a small Windows domain environment with a SIEM:

- **DC01 – Domain Controller**
  - Windows Server 2019
  - Active Directory Domain Services (AD DS)
  - DNS
  - Group Policy (GPO)
  - Sysmon logging

- **WIN10 – Domain-Joined Client**
  - Windows 10 Pro
  - Joined to AD domain
  - Sysmon installed
  - Used for user activity & attacks

- **Wazuh Server**
  - Wazuh Manager, Indexer, and Dashboard
  - Receives logs from DC01 and WIN10
  - Provides alerts + MITRE ATT&CK mapping

> 📊 See the full architecture and screenshots in the PDF report.

---

## 🔐 Hardening & Configuration

Key security controls implemented:

- Password complexity and minimum length
- Account lockout policy
- Disabled **LLMNR**
- Disabled **SMBv1**
- Blocked **PowerShell v2**
- Enforced custom desktop policy via GPO
- Installed **Sysmon** on DC01 and WIN10
- Forwarded Windows + Sysmon logs to **Wazuh**

---

## 💣 Attacks Simulated

All attacks were run from the domain-joined WIN10 machine (and/or attacker VM) against the AD environment to generate realistic log data.

- **Brute Force Attack**
  - Repeated failed logons (Event ID **4625**)
  - Detected by Wazuh as authentication failures

- **Kerberoasting**
  - Service ticket requests (Event ID **4769**)
  - Detected by Wazuh rules mapped to MITRE **T1558.003**

- **Privilege Escalation / DCSync-like Activity**
  - Elevated logons and directory replication-style access
  - Event IDs **4672**, **4662**
  - Visible in Sysmon + Wazuh

- **Persistence via Scheduled Task**
  - Creation of a malicious scheduled task
  - Event ID **4698**
  - Detected as suspicious persistence behavior

---

## 🛰 Detection & SIEM (Wazuh)

Wazuh was used as the central SIEM to:

- Ingest **Windows Event Logs** + **Sysmon** events
- Correlate events across DC01 and WIN10
- Trigger alerts on:
  - Excessive failed logons
  - Suspicious Kerberos activity
  - Privileged logons
  - Scheduled task creation
- Map alerts to **MITRE ATT&CK** techniques

Example detection coverage (from the report):

| Attack Type           | Event IDs        | Detection Source     | MITRE Technique |
|-----------------------|------------------|----------------------|-----------------|
| Brute Force           | 4625             | Wazuh                | T1110           |
| Kerberoasting         | 4769             | Wazuh                | T1558.003       |
| Privilege Escalation  | 4672, 4662       | Sysmon + Wazuh       | T1003           |
| Persistence (Task)    | 4698             | Wazuh                | T1053           |

---

## 🧠 Skills Demonstrated

This lab demonstrates:

- Active Directory deployment & hardening
- Group Policy design and enforcement
- Sysmon installation and event analysis
- Wazuh SIEM deployment and configuration
- Log correlation and detection engineering
- Mapping detections to **MITRE ATT&CK**
- Writing an investigation-style security report (PDF)

---

## 📎 Files in this Repository

- `Active-Directory-Wazuh-SIEM-Capstone.pdf` – Full project report with screenshots
- `images/` – Selected screenshots from the lab environment

---

## 🔮 Next Steps / Future Improvements

Some ideas to extend this lab:

- Add Linux servers or additional Windows clients
- Ingest logs into another SIEM (e.g., Elastic, Splunk) for comparison
- Add more attack techniques (lateral movement, pass-the-hash, etc.)
- Build Sigma rules or custom Wazuh rules for niche detections

---

If you have questions or want to discuss the lab, feel free to reach out!
