<#
.SYNOPSIS
    MDE Device Timeline SOC Analyzer
    Analyzes Microsoft Defender for Endpoint device timeline CSV exports for security threats.

.DESCRIPTION
    This script ingests an MDE Advanced Hunting device timeline CSV and produces a
    prioritized SOC analyst report covering:
      - Ransomware detections
      - Credential access (LSASS, SAM, browser credential theft)
      - Process injection & defense evasion
      - Data exfiltration signals
      - Suspicious network activity (non-standard ports, inbound connections, C2 indicators)
      - PowerShell & script-based execution
      - MITRE ATT&CK technique mapping
      - Persistence mechanisms (scheduled tasks, registry, services)
      - File & binary anomalies (mismatches, packed files)

.PARAMETER CsvPath
    Full path to the MDE device timeline CSV file.

.PARAMETER OutputPath
    (Optional) Path for the HTML report output. Defaults to the same directory as the CSV.

.PARAMETER Top
    (Optional) Number of items to show per finding category. Default: 10.

.EXAMPLE
    .\Analyze-MDETimeline.ps1 -CsvPath "C:\Cases\timeline.csv"

.EXAMPLE
    .\Analyze-MDETimeline.ps1 -CsvPath "C:\Cases\timeline.csv" -OutputPath "C:\Reports\soc-report.html" -Top 20

.NOTES
    Author  : SOC Automation
    Version : 1.0
    Requires: PowerShell 5.1+
    Input   : CSV exported from MDE Advanced Hunting (DeviceEvents / device timeline)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Path to the MDE device timeline CSV file.")]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$CsvPath,

    [Parameter(Mandatory = $false, HelpMessage = "Path for the HTML report output.")]
    [string]$OutputPath,

    [Parameter(Mandatory = $false, HelpMessage = "Max items to display per finding category.")]
    [int]$Top = 10
)

# ─────────────────────────────────────────────
# SETUP
# ─────────────────────────────────────────────
$ErrorActionPreference = "Stop"
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

if (-not $OutputPath) {
    $dir = Split-Path $CsvPath -Parent
    $base = [System.IO.Path]::GetFileNameWithoutExtension($CsvPath)
    $OutputPath = Join-Path $dir "${base}_SOC_Report.html"
}

Write-Host "`n[*] MDE Timeline SOC Analyzer v1.0" -ForegroundColor Cyan
Write-Host "[*] Loading CSV: $CsvPath" -ForegroundColor Cyan

$csv = Import-Csv -Path $CsvPath
$totalEvents = $csv.Count
$deviceName = ($csv | Select-Object -First 1).'Computer Name'
$machineId = ($csv | Select-Object -First 1).'Machine Id'
$timeRange = @{
    Start = ($csv | Sort-Object 'Event Time' | Select-Object -First 1).'Event Time'
    End   = ($csv | Sort-Object 'Event Time' -Descending | Select-Object -First 1).'Event Time'
}

Write-Host "[*] Device: $deviceName ($machineId)" -ForegroundColor Cyan
Write-Host "[*] Events: $totalEvents | Range: $($timeRange.Start) to $($timeRange.End)" -ForegroundColor Cyan
Write-Host "[*] Analyzing..." -ForegroundColor Yellow

# ─────────────────────────────────────────────
# CATEGORY DEFINITIONS
# ─────────────────────────────────────────────

# Critical action types that always warrant investigation
$criticalActions = @(
    'RansomwareBehaviorDetectedInTheFileSystem'
    'SuspiciousAccessToLSASSService'
    'SuspiciousProcessDataExfiltration'
    'PossibleTheftOfSensitiveWebBrowserInformation'
)

# High-risk action types
$highActions = @(
    'RemoteCreateThreadCrossProcessInjection'
    'SamFileAccess'
    'ExploitGuardNetworkProtectionBlocked'
    'OutboundConnectionFromLowPrevalenceProcessToUncommonlyUsedPort'
    'InboundConnectionAccepted'
    'MasqueradedScheduledTask'
    'DefenderObfuscation'
    'ProcessPrimaryTokenModified'
    'NtAllocateVirtualMemoryRemoteApiCall'
)

# Medium-risk action types
$mediumActions = @(
    'NetworkFilterConnectionInfoProtocolNonStandardPort'
    'MismatchingOriginalNameWindowsDll'
    'MismatchingOriginalNameWindowsBinary'
    'CommonFileNameDropSignerMismatch'
    'FileCouldBePacked'
    'AmsiContentDetails'
    'AmsiContentPattern'
    'ClrUnbackedModuleLoaded'
)

# Network event action types
$networkActions = @(
    'ConnectionSuccess', 'ConnectionSuccessAggregatedReport', 'ConnectionAcknowledged'
    'ConnectionFailed', 'ConnectionFailedAggregatedReport', 'ConnectionAttempt', 'ConnectionFound'
    'NetworkSignatureInspected', 'NetworkPortProtocolWeb'
    'DnsConnectionInspected', 'DnsQueryResponse'
    'SslConnectionInspected', 'HttpConnectionInspected', 'IcmpConnectionInspected'
    'ListeningConnectionCreated', 'InboundConnectionAccepted'
    'NetworkFilterConnectionInfo', 'NetworkFilterConnectionInfoProtocolNonStandardPort'
    'ExploitGuardNetworkProtectionBlocked'
    'OutboundConnectionFromLowPrevalenceProcessToUncommonlyUsedPort'
    'SystemNetworkConfigurationDiscoveryCommand'
)

# ─────────────────────────────────────────────
# ANALYSIS FUNCTIONS
# ─────────────────────────────────────────────

function Get-FindingsByAction {
    param([string[]]$ActionTypes, $Data)
    $Data | Where-Object { $_.'Action Type' -in $ActionTypes }
}

function Get-ExternalIPs {
    param($Events)
    $Events |
        Where-Object { $_.'Remote IP' -ne '' } |
        Where-Object { $_.'Remote IP' -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|::1$|fe80|fd|::$)' } |
        Group-Object 'Remote IP' |
        Sort-Object Count -Descending |
        ForEach-Object {
            [PSCustomObject]@{
                IP          = $_.Name
                Connections = $_.Count
                Ports       = (($_.Group | Select-Object -ExpandProperty 'Remote Port' -Unique | Where-Object { $_ -ne '' } | Sort-Object) -join ', ')
                Processes   = (($_.Group | Select-Object -ExpandProperty 'File Name' -Unique | Where-Object { $_ -ne '' }) -join ', ')
            }
        }
}

function Get-MitreMapping {
    param($Data)
    $Data |
        Where-Object { $_.Categories -ne '' } |
        Group-Object Categories |
        Sort-Object Count -Descending |
        ForEach-Object {
            # Extract technique IDs from the categories string
            $techniques = [regex]::Matches($_.Name, 'T\d{4}(\.\d{3})?') | ForEach-Object { $_.Value }
            [PSCustomObject]@{
                RawCategory  = $_.Name
                Techniques   = ($techniques -join ', ')
                Count        = $_.Count
            }
        }
}

# ─────────────────────────────────────────────
# RUN ANALYSIS
# ─────────────────────────────────────────────

Write-Host "[*] Categorizing threat events..." -ForegroundColor Yellow

# 1. Event type breakdown
$actionBreakdown = $csv | Group-Object 'Action Type' | Sort-Object Count -Descending

# 2. Critical findings
$ransomware       = Get-FindingsByAction -ActionTypes @('RansomwareBehaviorDetectedInTheFileSystem') -Data $csv
$lsassAccess      = Get-FindingsByAction -ActionTypes @('SuspiciousAccessToLSASSService') -Data $csv
$dataExfil        = Get-FindingsByAction -ActionTypes @('SuspiciousProcessDataExfiltration') -Data $csv
$browserTheft     = Get-FindingsByAction -ActionTypes @('PossibleTheftOfSensitiveWebBrowserInformation') -Data $csv

# 3. High findings
$processInjection = Get-FindingsByAction -ActionTypes @('RemoteCreateThreadCrossProcessInjection') -Data $csv
$samAccess        = Get-FindingsByAction -ActionTypes @('SamFileAccess') -Data $csv
$exploitGuard     = Get-FindingsByAction -ActionTypes @('ExploitGuardNetworkProtectionBlocked') -Data $csv
$lowPrevConn      = Get-FindingsByAction -ActionTypes @('OutboundConnectionFromLowPrevalenceProcessToUncommonlyUsedPort') -Data $csv
$inboundConn      = Get-FindingsByAction -ActionTypes @('InboundConnectionAccepted') -Data $csv
$masqTasks        = Get-FindingsByAction -ActionTypes @('MasqueradedScheduledTask') -Data $csv
$obfuscation      = Get-FindingsByAction -ActionTypes @('DefenderObfuscation') -Data $csv
$tokenMod         = Get-FindingsByAction -ActionTypes @('ProcessPrimaryTokenModified') -Data $csv
$remoteAlloc      = Get-FindingsByAction -ActionTypes @('NtAllocateVirtualMemoryRemoteApiCall') -Data $csv

# 4. Medium findings
$nonStdPort       = Get-FindingsByAction -ActionTypes @('NetworkFilterConnectionInfoProtocolNonStandardPort') -Data $csv
$nameMismatch     = Get-FindingsByAction -ActionTypes @('MismatchingOriginalNameWindowsDll','MismatchingOriginalNameWindowsBinary','CommonFileNameDropSignerMismatch') -Data $csv
$packed           = Get-FindingsByAction -ActionTypes @('FileCouldBePacked') -Data $csv
$amsi             = Get-FindingsByAction -ActionTypes @('AmsiContentDetails','AmsiContentPattern') -Data $csv
$clrUnbacked      = Get-FindingsByAction -ActionTypes @('ClrUnbackedModuleLoaded') -Data $csv

# 5. PowerShell activity
$powershell       = Get-FindingsByAction -ActionTypes @('PowershellExecution','PowerShellCommand') -Data $csv

# 6. Persistence
$schedTasks       = $csv | Where-Object { $_.'Action Type' -match 'ScheduledTask' }
$services         = $csv | Where-Object { $_.'Action Type' -match 'ServiceCreation|NewServiceStarted' }
$asep             = Get-FindingsByAction -ActionTypes @('AsepByRegistry') -Data $csv

# 7. Network analysis
$netEvents        = Get-FindingsByAction -ActionTypes $networkActions -Data $csv
$externalIPs      = Get-ExternalIPs -Events $netEvents

# 8. MITRE mapping
$mitre            = Get-MitreMapping -Data $csv

# 9. User activity
$users = $csv | Where-Object { $_.'Account Name' -ne '' } |
    Group-Object @{E={"$($_.'Account Domain')\$($_.'Account Name')"}} |
    Sort-Object Count -Descending

# 10. Logon events
$logonSuccess = Get-FindingsByAction -ActionTypes @('LogonSuccess') -Data $csv
$logonFailed  = Get-FindingsByAction -ActionTypes @('LogonFailed') -Data $csv
$logoffEvents = Get-FindingsByAction -ActionTypes @('LogoffSuccess','Logoff') -Data $csv

Write-Host "[*] Building severity scores..." -ForegroundColor Yellow

# ─────────────────────────────────────────────
# SEVERITY SCORING
# ─────────────────────────────────────────────

$findings = @()

# Score each finding category
$findingDefs = @(
    @{ Name='Ransomware Detection';              Severity='CRITICAL'; Events=$ransomware;       MITRE='T1486'; Weight=100 }
    @{ Name='LSASS Credential Access';            Severity='CRITICAL'; Events=$lsassAccess;      MITRE='T1003.001'; Weight=95 }
    @{ Name='Data Exfiltration Signals';          Severity='CRITICAL'; Events=$dataExfil;        MITRE='T1041'; Weight=90 }
    @{ Name='Browser Credential Theft';           Severity='CRITICAL'; Events=$browserTheft;     MITRE='T1555.003'; Weight=85 }
    @{ Name='Cross-Process Injection';            Severity='HIGH';     Events=$processInjection; MITRE='T1055'; Weight=80 }
    @{ Name='SAM Database Access';                Severity='HIGH';     Events=$samAccess;         MITRE='T1003.002'; Weight=78 }
    @{ Name='Remote Memory Allocation';           Severity='HIGH';     Events=$remoteAlloc;       MITRE='T1055'; Weight=75 }
    @{ Name='Token Manipulation';                 Severity='HIGH';     Events=$tokenMod;          MITRE='T1134'; Weight=72 }
    @{ Name='Defender Obfuscation Evasion';       Severity='HIGH';     Events=$obfuscation;       MITRE='T1027'; Weight=70 }
    @{ Name='Low-Prevalence Outbound Connections';Severity='HIGH';     Events=$lowPrevConn;       MITRE='T1571'; Weight=68 }
    @{ Name='Masqueraded Scheduled Tasks';        Severity='HIGH';     Events=$masqTasks;         MITRE='T1036.004'; Weight=65 }
    @{ Name='Inbound Connections Accepted';       Severity='HIGH';     Events=$inboundConn;       MITRE='T1219'; Weight=63 }
    @{ Name='Exploit Guard Blocks';               Severity='MEDIUM';   Events=$exploitGuard;      MITRE='N/A'; Weight=55 }
    @{ Name='Non-Standard Port Traffic';          Severity='MEDIUM';   Events=$nonStdPort;        MITRE='T1571'; Weight=50 }
    @{ Name='Binary Name / Signer Mismatch';      Severity='MEDIUM';   Events=$nameMismatch;      MITRE='T1036'; Weight=48 }
    @{ Name='AMSI Detections';                    Severity='MEDIUM';   Events=$amsi;              MITRE='T1059'; Weight=45 }
    @{ Name='CLR Unbacked Module Loading';        Severity='MEDIUM';   Events=$clrUnbacked;       MITRE='T1620'; Weight=42 }
    @{ Name='Packed / Compressed Files';          Severity='MEDIUM';   Events=$packed;            MITRE='T1027.002'; Weight=40 }
    @{ Name='PowerShell Execution';               Severity='INFO';     Events=$powershell;        MITRE='T1059.001'; Weight=30 }
)

foreach ($def in $findingDefs) {
    $count = @($def.Events).Count
    if ($count -gt 0) {
        $findings += [PSCustomObject]@{
            Name     = $def.Name
            Severity = $def.Severity
            Count    = $count
            MITRE    = $def.MITRE
            Weight   = $def.Weight
            Events   = $def.Events
        }
    }
}

$findings = $findings | Sort-Object Weight -Descending

# Calculate overall risk score (0-100)
$riskTotal = 0
foreach ($f in $findings) {
    $multiplier = switch ($f.Severity) {
        'CRITICAL' { 1.0 }
        'HIGH'     { 0.5 }
        'MEDIUM'   { 0.2 }
        default    { 0.05 }
    }
    $riskTotal += $f.Weight * $multiplier
}
$riskScore = [math]::Min(100, [math]::Round($riskTotal / 5))

$riskLabel = if ($riskScore -ge 80) { 'CRITICAL' }
    elseif ($riskScore -ge 60) { 'HIGH' }
    elseif ($riskScore -ge 35) { 'MEDIUM' }
    else { 'LOW' }

Write-Host "[*] Risk Score: $riskScore/100 ($riskLabel)" -ForegroundColor $(
    switch ($riskLabel) { 'CRITICAL' { 'Red' } 'HIGH' { 'DarkYellow' } 'MEDIUM' { 'Yellow' } default { 'Green' } }
)

# ─────────────────────────────────────────────
# HELPER: HTML ESCAPE
# ─────────────────────────────────────────────
function HtmlEncode([string]$s) {
    [System.Net.WebUtility]::HtmlEncode($s)
}

function Truncate([string]$s, [int]$len = 120) {
    if ($s.Length -gt $len) { $s.Substring(0, $len) + '...' } else { $s }
}

# ─────────────────────────────────────────────
# BUILD HTML REPORT
# ─────────────────────────────────────────────

Write-Host "[*] Generating HTML report..." -ForegroundColor Yellow

$sevColors = @{
    CRITICAL = '#f85149'
    HIGH     = '#d29922'
    MEDIUM   = '#e3b341'
    INFO     = '#58a6ff'
    LOW      = '#3fb950'
}

# Build findings HTML
$findingsHtml = ""
foreach ($f in $findings) {
    $color = $sevColors[$f.Severity]
    $detailRows = ""

    $sample = @($f.Events) | Select-Object -First $Top
    foreach ($e in $sample) {
        $time      = HtmlEncode ($e.'Event Time')
        $action    = HtmlEncode ($e.'Action Type')
        $proc      = HtmlEncode ($e.'Initiating Process File Name')
        if (-not $proc) { $proc = HtmlEncode ($e.'File Name') }
        $path      = HtmlEncode (Truncate ($e.'Initiating Process Folder Path'))
        if (-not $path) { $path = HtmlEncode (Truncate ($e.'Folder Path')) }
        $cmdline   = HtmlEncode (Truncate ($e.'Initiating Process Command Line') 150)
        if (-not $cmdline) { $cmdline = HtmlEncode (Truncate ($e.'Process Command Line') 150) }
        $user      = HtmlEncode ("$($e.'Initiating Process Account Domain')\$($e.'Initiating Process Account Name')")
        if ($user -eq '\') { $user = HtmlEncode ("$($e.'Account Domain')\$($e.'Account Name')") }
        $remoteIP  = HtmlEncode ($e.'Remote IP')
        $remotePort= HtmlEncode ($e.'Remote Port')
        $remote    = if ($remoteIP) { "${remoteIP}:${remotePort}" } else { '-' }

        $detailRows += @"
            <tr>
              <td class="mono">$time</td>
              <td>$proc</td>
              <td class="mono small">$cmdline</td>
              <td>$user</td>
              <td class="mono">$remote</td>
            </tr>
"@
    }

    $moreNote = ""
    $totalCount = @($f.Events).Count
    if ($totalCount -gt $Top) {
        $moreNote = "<p class='muted'>Showing $Top of $totalCount events.</p>"
    }

    $findingsHtml += @"
    <div class="finding" style="border-left-color: $color;">
      <div class="finding-header">
        <span class="sev-badge" style="background: $color;">$($f.Severity)</span>
        <span class="finding-title">$($f.Name)</span>
        <span class="finding-count">$totalCount events</span>
        <span class="mitre-tag">$($f.MITRE)</span>
      </div>
      <table class="detail-table">
        <thead>
          <tr><th>Time</th><th>Process</th><th>Command Line</th><th>User</th><th>Remote</th></tr>
        </thead>
        <tbody>$detailRows</tbody>
      </table>
      $moreNote
    </div>
"@
}

# Build network summary HTML
$netSummaryRows = ""
foreach ($ip in ($externalIPs | Select-Object -First 30)) {
    $netSummaryRows += @"
      <tr>
        <td class="mono">$(HtmlEncode $ip.IP)</td>
        <td>$($ip.Connections)</td>
        <td class="mono">$(HtmlEncode $ip.Ports)</td>
        <td>$(HtmlEncode $ip.Processes)</td>
      </tr>
"@
}

# Build MITRE HTML
$mitreRows = ""
foreach ($m in ($mitre | Select-Object -First 20)) {
    $mitreRows += @"
      <tr>
        <td class="mono">$(HtmlEncode $m.Techniques)</td>
        <td>$($m.Count)</td>
        <td class="small">$(HtmlEncode (Truncate $m.RawCategory 100))</td>
      </tr>
"@
}

# Build action type breakdown HTML
$actionRows = ""
foreach ($a in ($actionBreakdown | Select-Object -First 30)) {
    $isSuspicious = ($a.Name -in ($criticalActions + $highActions + $mediumActions))
    $highlight = if ($isSuspicious) { ' class="highlight"' } else { '' }
    $actionRows += @"
      <tr$highlight>
        <td>$(HtmlEncode $a.Name)</td>
        <td>$($a.Count)</td>
      </tr>
"@
}

# Build user activity HTML
$userRows = ""
foreach ($u in ($users | Select-Object -First 15)) {
    $userRows += @"
      <tr>
        <td>$(HtmlEncode $u.Name)</td>
        <td>$($u.Count)</td>
      </tr>
"@
}

# Build logon/logoff detail rows
$logonLogoffRows = ""
foreach ($ll in ($logonLogoffAll | Select-Object -First 30)) {
    $typeColor = switch ($ll.Type) { 'Logon Success' { '#3fb950' } 'Logon Failed' { '#f85149' } 'Logoff' { '#8b949e' } default { '#e6edf3' } }
    $logonLogoffRows += @"
      <tr>
        <td class="mono">$(HtmlEncode $ll.Time)</td>
        <td style="color:$typeColor;font-weight:600;">$(HtmlEncode $ll.Type)</td>
        <td>$(HtmlEncode $ll.User)</td>
      </tr>
"@
}

# 11. Logon/Logoff detail for user activity section
$logonLogoffAll = @()
foreach ($e in @($logonSuccess)) {
    $logonLogoffAll += [PSCustomObject]@{
        Time = $e.'Event Time'
        Type = 'Logon Success'
        User = "$($e.'Account Domain')\$($e.'Account Name')"
    }
}
foreach ($e in @($logonFailed)) {
    $logonLogoffAll += [PSCustomObject]@{
        Time = $e.'Event Time'
        Type = 'Logon Failed'
        User = "$($e.'Account Domain')\$($e.'Account Name')"
    }
}
foreach ($e in @($logoffEvents)) {
    $logonLogoffAll += [PSCustomObject]@{
        Time = $e.'Event Time'
        Type = 'Logoff'
        User = "$($e.'Account Domain')\$($e.'Account Name')"
    }
}
$logonLogoffAll = $logonLogoffAll | Sort-Object Time

# Risk gauge color
$riskColor = $sevColors[$riskLabel]

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Analysis — $deviceName</title>
<style>
  :root { --bg:#0d1117; --surface:#161b22; --border:#30363d; --text:#e6edf3; --muted:#8b949e; }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif; background:var(--bg); color:var(--text); line-height:1.6; padding:2rem; max-width:1100px; margin:0 auto; }
  h1 { font-size:1.6rem; margin-bottom:0.25rem; }
  h2 { font-size:1.2rem; margin:2rem 0 1rem; padding-bottom:0.5rem; border-bottom:1px solid var(--border); }
  .meta { color:var(--muted); font-size:0.85rem; margin-bottom:1.5rem; }
  .meta span { margin-right:1.5rem; }

  /* Risk Score Banner */
  .risk-banner { background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:1.5rem; margin-bottom:2rem; display:flex; align-items:center; gap:1.5rem; }
  .risk-score { font-size:2.5rem; font-weight:700; min-width:80px; text-align:center; }
  .risk-details { flex:1; }
  .risk-details .label { font-size:0.8rem; color:var(--muted); text-transform:uppercase; letter-spacing:0.05em; }
  .risk-bar { height:8px; background:#30363d; border-radius:4px; margin-top:0.5rem; overflow:hidden; }
  .risk-fill { height:100%; border-radius:4px; }

  /* Summary Cards */
  .summary-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:0.75rem; margin-bottom:2rem; }
  .summary-card { background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:1rem; text-align:center; }
  .summary-card .num { font-size:1.5rem; font-weight:700; }
  .summary-card .lbl { font-size:0.75rem; color:var(--muted); }

  /* Findings */
  .finding { background:var(--surface); border:1px solid var(--border); border-left:4px solid; border-radius:6px; padding:1.25rem; margin-bottom:1rem; }
  .finding-header { display:flex; align-items:center; gap:0.75rem; flex-wrap:wrap; margin-bottom:0.75rem; }
  .sev-badge { padding:0.15rem 0.6rem; border-radius:4px; font-size:0.7rem; font-weight:700; color:#fff; }
  .finding-title { font-weight:600; font-size:1rem; }
  .finding-count { color:var(--muted); font-size:0.8rem; }
  .mitre-tag { background:#30363d; color:#58a6ff; padding:0.1rem 0.5rem; border-radius:3px; font-size:0.7rem; font-family:monospace; }

  /* Tables */
  table { width:100%; border-collapse:collapse; font-size:0.8rem; }
  th { text-align:left; color:var(--muted); font-weight:600; padding:0.4rem 0.5rem; border-bottom:1px solid var(--border); font-size:0.7rem; text-transform:uppercase; }
  td { padding:0.35rem 0.5rem; border-bottom:1px solid #21262d; vertical-align:top; word-break:break-word; }
  .detail-table { margin-top:0.5rem; }
  .mono { font-family:'Cascadia Code',Consolas,monospace; font-size:0.78rem; }
  .small { font-size:0.72rem; color:var(--muted); max-width:350px; }
  .highlight td { background:#f8514910; }
  .muted { color:var(--muted); font-size:0.78rem; margin-top:0.5rem; }

  /* Sections */
  .section { background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:1.25rem; margin-bottom:1rem; overflow-x:auto; }

  @media (max-width:768px) { body { padding:1rem; } .risk-banner { flex-direction:column; } }
  @media print { body { background:#fff; color:#000; } .finding { break-inside:avoid; } }
</style>
</head>
<body>

<h1>🛡️ SOC Threat Analysis Report</h1>
<div class="meta">
  <span><strong>Device:</strong> $deviceName</span>
  <span><strong>Machine ID:</strong> $(if ($machineId) { $machineId.Substring(0, [math]::Min(12, $machineId.Length)) + '...' } else { 'N/A' })</span>
  <span><strong>Period:</strong> $($timeRange.Start) — $($timeRange.End)</span>
  <span><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</span>
</div>

<!-- Risk Score -->
<div class="risk-banner">
  <div class="risk-score" style="color:$riskColor;">$riskScore</div>
  <div class="risk-details">
    <div class="label">Overall Risk Score</div>
    <div style="font-size:1.1rem;font-weight:600;color:$riskColor;">$riskLabel</div>
    <div class="risk-bar"><div class="risk-fill" style="width:${riskScore}%;background:$riskColor;"></div></div>
    <div class="muted" style="margin-top:0.5rem;">Based on $($findings.Count) distinct finding categories across $totalEvents total events.</div>
  </div>
</div>

<!-- Summary Cards -->
<div class="summary-grid">
  <div class="summary-card"><div class="num" style="color:#f85149;">$(@($findings | Where-Object Severity -eq 'CRITICAL').Count)</div><div class="lbl">Critical</div></div>
  <div class="summary-card"><div class="num" style="color:#d29922;">$(@($findings | Where-Object Severity -eq 'HIGH').Count)</div><div class="lbl">High</div></div>
  <div class="summary-card"><div class="num" style="color:#e3b341;">$(@($findings | Where-Object Severity -eq 'MEDIUM').Count)</div><div class="lbl">Medium</div></div>
  <div class="summary-card"><div class="num">$totalEvents</div><div class="lbl">Total Events</div></div>
  <div class="summary-card"><div class="num">$(@($externalIPs).Count)</div><div class="lbl">External IPs</div></div>
  <div class="summary-card"><div class="num">$(@($netEvents).Count)</div><div class="lbl">Network Events</div></div>
</div>

<!-- Findings -->
<h2>🔍 Findings by Severity</h2>
$findingsHtml

<!-- MITRE ATT&CK -->
<h2>🗺️ MITRE ATT&CK Mapping (Top 20)</h2>
<div class="section">
<table>
  <thead><tr><th>Techniques</th><th>Count</th><th>Category</th></tr></thead>
  <tbody>$mitreRows</tbody>
</table>
</div>

<!-- External IPs -->
<h2>🌐 Top External IP Addresses (Top 30)</h2>
<div class="section">
<table>
  <thead><tr><th>Remote IP</th><th>Connections</th><th>Ports</th><th>Processes</th></tr></thead>
  <tbody>$netSummaryRows</tbody>
</table>
<p class="muted">Total unique external IPs: $(@($externalIPs).Count)</p>
</div>

<!-- User Activity -->
<h2>👤 User Activity Summary</h2>
<div class="section">
<table>
  <thead><tr><th>User</th><th>Events</th></tr></thead>
  <tbody>$userRows</tbody>
</table>
<p class="muted">Logon successes: $(@($logonSuccess).Count) | Logon failures: $(@($logonFailed).Count) | Logoff events: $(@($logoffEvents).Count)</p>
</div>

<!-- Logon / Logoff Details -->
<h2>🔐 Logon &amp; Logoff Activity</h2>
<div class="section">
<table>
  <thead><tr><th>Time</th><th>Event</th><th>User</th></tr></thead>
  <tbody>$logonLogoffRows</tbody>
</table>
<p class="muted">Showing up to 30 logon/logoff events sorted by time.</p>
</div>

<!-- Action Type Breakdown -->
<h2>📊 Event Type Breakdown (Top 30)</h2>
<div class="section">
<table>
  <thead><tr><th>Action Type</th><th>Count</th></tr></thead>
  <tbody>$actionRows</tbody>
</table>
<p class="muted">Highlighted rows indicate security-relevant action types.</p>
</div>

<div class="muted" style="text-align:center; margin-top:2rem; padding-top:1rem; border-top:1px solid var(--border);">
  MDE Timeline SOC Analyzer v1.0 &nbsp;·&nbsp; Analysis completed in $([math]::Round($stopwatch.Elapsed.TotalSeconds, 1))s &nbsp;·&nbsp; Showing top $Top events per finding
</div>

</body>
</html>
"@

$html | Out-File -FilePath $OutputPath -Encoding UTF8
$stopwatch.Stop()

Write-Host "[*] Report saved to: $OutputPath" -ForegroundColor Green
Write-Host "[*] Opening report in browser..." -ForegroundColor Cyan
Start-Process $OutputPath
Write-Host "[*] Completed in $([math]::Round($stopwatch.Elapsed.TotalSeconds, 1)) seconds.`n" -ForegroundColor Cyan

# ─────────────────────────────────────────────
# CONSOLE SUMMARY
# ─────────────────────────────────────────────
Write-Host "═══════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "  RISK SCORE: $riskScore/100 ($riskLabel)" -ForegroundColor $(
    switch ($riskLabel) { 'CRITICAL' { 'Red' } 'HIGH' { 'DarkYellow' } 'MEDIUM' { 'Yellow' } default { 'Green' } }
)
Write-Host "═══════════════════════════════════════════════" -ForegroundColor DarkGray

foreach ($f in $findings) {
    $icon = switch ($f.Severity) { 'CRITICAL' { '[!!]' } 'HIGH' { '[!]' } 'MEDIUM' { '[~]' } default { '[i]' } }
    $fg   = switch ($f.Severity) { 'CRITICAL' { 'Red' } 'HIGH' { 'DarkYellow' } 'MEDIUM' { 'Yellow' } default { 'Cyan' } }
    Write-Host "  $icon " -ForegroundColor $fg -NoNewline
    Write-Host "$($f.Name): $(@($f.Events).Count) events ($($f.MITRE))"
}

Write-Host "`n  External IPs: $(@($externalIPs).Count) | Network Events: $(@($netEvents).Count) | Total Events: $totalEvents" -ForegroundColor DarkGray
Write-Host ""
