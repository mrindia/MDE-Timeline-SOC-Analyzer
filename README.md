# 🛡️ MDE Timeline SOC Analyzer

A PowerShell-based security analysis tool that ingests **Microsoft Defender for Endpoint (MDE)** device timeline CSV exports and produces a prioritized, interactive HTML threat report for SOC analysts.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?logo=windows)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📸 Sample Output

The tool generates a dark-themed, responsive HTML report featuring:

- **Risk Score Banner** — Overall 0–100 risk score with color-coded severity (CRITICAL / HIGH / MEDIUM / LOW)
- **Summary Cards** — At-a-glance counts for critical, high, medium findings, total events, external IPs, and network events
- **Findings by Severity** — Detailed event tables per finding category with process, command line, user, and remote connection info
- **MITRE ATT&CK Mapping** — Automatic technique extraction and mapping
- **External IP Summary** — Top external IPs with connection counts, ports, and associated processes
- **User Activity Summary** — Active accounts and event counts
- **Logon & Logoff Activity** — Timestamped table showing which users logged on/off with color-coded event types
- **Event Type Breakdown** — Full action type distribution with highlighted security-relevant rows

---

## 🚀 Quick Start

### Prerequisites

- **PowerShell 5.1+** (ships with Windows 10/11)
- An MDE device timeline CSV export from Advanced Hunting

### Using the PowerShell Script

```powershell
.\Analyze-MDETimeline.ps1 -CsvPath "C:\Cases\timeline.csv"
```

### Using the Executable

```powershell
.\Analyze-MDETimeline.exe -CsvPath "C:\Cases\timeline.csv"
```

The HTML report will be generated in the same directory as the CSV and **automatically opened in your default browser**.

---

## 📋 Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-CsvPath` | ✅ Yes | — | Full path to the MDE device timeline CSV file |
| `-OutputPath` | No | `<CsvName>_SOC_Report.html` | Custom path for the HTML report output |
| `-Top` | No | `10` | Number of sample events shown per finding category |

### Examples

```powershell
# Basic usage — report saved next to the CSV
.\Analyze-MDETimeline.ps1 -CsvPath "C:\Cases\timeline.csv"

# Custom output path and show 20 events per category
.\Analyze-MDETimeline.ps1 -CsvPath "C:\Cases\timeline.csv" -OutputPath "C:\Reports\soc-report.html" -Top 20
```

---

## 🔍 Detection Categories

### Critical Severity
| Finding | MITRE ATT&CK |
|---------|---------------|
| Ransomware Detection | T1486 |
| LSASS Credential Access | T1003.001 |
| Data Exfiltration Signals | T1041 |
| Browser Credential Theft | T1555.003 |

### High Severity
| Finding | MITRE ATT&CK |
|---------|---------------|
| Cross-Process Injection | T1055 |
| SAM Database Access | T1003.002 |
| Remote Memory Allocation | T1055 |
| Token Manipulation | T1134 |
| Defender Obfuscation Evasion | T1027 |
| Low-Prevalence Outbound Connections | T1571 |
| Masqueraded Scheduled Tasks | T1036.004 |
| Inbound Connections Accepted | T1219 |

### Medium Severity
| Finding | MITRE ATT&CK |
|---------|---------------|
| Exploit Guard Blocks | N/A |
| Non-Standard Port Traffic | T1571 |
| Binary Name / Signer Mismatch | T1036 |
| AMSI Detections | T1059 |
| CLR Unbacked Module Loading | T1620 |
| Packed / Compressed Files | T1027.002 |

### Informational
| Finding | MITRE ATT&CK |
|---------|---------------|
| PowerShell Execution | T1059.001 |

---

## 📊 Risk Scoring

The overall risk score (0–100) is calculated by weighting each finding category:

| Severity | Multiplier |
|----------|-----------|
| CRITICAL | 1.0× |
| HIGH | 0.5× |
| MEDIUM | 0.2× |
| INFO | 0.05× |

**Risk Labels:**
- 🔴 **CRITICAL** — Score ≥ 80
- 🟠 **HIGH** — Score ≥ 60
- 🟡 **MEDIUM** — Score ≥ 35
- 🟢 **LOW** — Score < 35

---

## 🌐 Network Analysis

The tool automatically:
- Filters out internal/private IP ranges (RFC 1918, loopback, link-local)
- Groups external IPs by connection count
- Identifies ports and processes per remote IP
- Flags non-standard port traffic and low-prevalence outbound connections

---

## 📁 CSV Input Format

The tool expects a CSV exported from MDE Advanced Hunting with standard device timeline columns including:

- `Event Time`, `Action Type`, `Computer Name`, `Machine Id`
- `File Name`, `Folder Path`, `Initiating Process File Name`
- `Initiating Process Command Line`, `Process Command Line`
- `Account Name`, `Account Domain`
- `Remote IP`, `Remote Port`
- `Categories` (for MITRE mapping)

---

## 🛠️ Building the Executable

To compile the PowerShell script into a standalone `.exe`:

```powershell
Install-Module -Name ps2exe -Scope CurrentUser
Invoke-ps2exe -inputFile ".\Analyze-MDETimeline.ps1" -outputFile ".\Analyze-MDETimeline.exe" -title "MDE Timeline SOC Analyzer" -description "Analyzes MDE device timeline CSV exports for security threats" -version "1.0.0.0"
```

---

## 📄 License

This project is licensed under the MIT License.
