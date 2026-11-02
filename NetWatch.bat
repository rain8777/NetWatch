@echo off
setlocal
title NetWatch - Windows Internet Activity Monitor
set "NW_SELF=%~f0"
where powershell.exe >nul 2>&1
if errorlevel 1 (echo PowerShell was not found. NetWatch requires Windows PowerShell 5.1.& pause& exit /b 1)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$t=[IO.File]::ReadAllText($env:NW_SELF);$m='#==PS_'+'BEGIN==';$i=$t.IndexOf($m)+$m.Length;& ([scriptblock]::Create($t.Substring($i)))"
set "NW_RC=%ERRORLEVEL%"
endlocal & exit /b %NW_RC%
#==PS_BEGIN==
# ============================================================================
# NETWATCH 1.0 - Windows internet activity monitor, diagnostic and repair tool
# Layers: MONITOR (read-only) > INVESTIGATE (read-only) > REPAIR (approval only)
# All data stays local in %LOCALAPPDATA%\NetWatch. Nothing is uploaded.
# ============================================================================
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Script:Ver = '1.0.0'
$Script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Script:Root = Join-Path $env:LOCALAPPDATA 'NetWatch'
$Script:Dirs = @{ Logs = 'logs'; Reports = 'reports'; Quarantine = 'quarantine'; Backups = 'backups'; Data = 'data' }
foreach ($k in @($Script:Dirs.Keys)) {
    $p = Join-Path $Script:Root $Script:Dirs[$k]
    New-Item -ItemType Directory -Force -Path $p | Out-Null
    $Script:Dirs[$k] = $p
}
$Script:SessionId = Get-Date -Format 'yyyyMMdd_HHmmss'
$Script:LogFile = Join-Path $Script:Dirs.Logs ("session_{0}.log" -f $Script:SessionId)
$Script:EventsCsv = Join-Path $Script:Dirs.Logs 'events.csv'
$Script:ClsFile = Join-Path $Script:Dirs.Data 'classification_history.jsonl'
$Script:DisabledFile = Join-Path $Script:Dirs.Data 'disabled_startup.json'
$Script:CfgPath = Join-Path $Script:Dirs.Data 'config.json'
$Script:Cfg = [ordered]@{ IntervalSec = 2; RetentionDays = 30; MaxLogMB = 20; BurstMBps = 5; BurstFactor = 4; ConnectivityEveryTicks = 15 }
$Script:SigCache = @{}
$Script:Findings = New-Object System.Collections.ArrayList
$Script:SessionCls = New-Object System.Collections.ArrayList
$Script:ClsLast = @{}
$Script:Recent = New-Object 'System.Collections.Generic.List[string]'
$Script:Seen = @{}
$Script:StartupCache = $null
$Script:AvPaths = $null
$Script:LastLevel = ''
$Script:OnlineAt = $null
$Script:EtwActive = $false
$Script:LastBw = $null
$Script:EtwName = 'NetWatchKN'
$Script:EtwFile = Join-Path $env:TEMP ("netwatch_{0}.etl" -f $Script:SessionId)

try {
    $sz = $Host.UI.RawUI.WindowSize
    if ($sz.Width -lt 120) {
        $b = $Host.UI.RawUI.BufferSize
        $Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size(120, [math]::Max($b.Height, 3000))
        $Host.UI.RawUI.WindowSize = New-Object Management.Automation.Host.Size(120, [math]::Min(45, $Host.UI.RawUI.MaxPhysicalWindowSize.Height))
    }
} catch {}

# ---------------------------------------------------------------- UI helpers
function Say($t, $c = 'Gray') { Write-Host $t -ForegroundColor $c }
function Head($t) {
    Clear-Host
    Write-Host ('=' * 100) -ForegroundColor Cyan
    Write-Host (" NETWATCH | {0}" -f $t) -ForegroundColor Cyan
    Write-Host ('=' * 100) -ForegroundColor Cyan
    if (-not $Script:IsAdmin) { Say ' [Not running as Administrator: some data and all admin-only repairs are unavailable]' DarkYellow }
}
function Pause-Menu { Say ''; [void](Read-Host ' Press Enter to continue') }
function Confirm-Action($prompt) { $a = Read-Host ("{0} [type YES to approve, anything else cancels]" -f $prompt); return ($a -ceq 'YES') }
function Ask-Int($prompt, $default) { $a = Read-Host $prompt; $n = 0; if ([int]::TryParse($a, [ref]$n)) { return $n } else { return $default } }
function Fmt-Bytes($b) {
    $b = [double]$b
    if ($b -ge 1GB) { return ('{0:N2} GB' -f ($b / 1GB)) }
    if ($b -ge 1MB) { return ('{0:N2} MB' -f ($b / 1MB)) }
    if ($b -ge 1KB) { return ('{0:N1} KB' -f ($b / 1KB)) }
    return ('{0:N0} B' -f $b)
}
function Fmt-Rate($bps) { return ((Fmt-Bytes $bps) + '/s') }
function Show-Table($objs, [string[]]$cols) {
    if (-not $objs -or @($objs).Count -eq 0) { Say '   (none)' DarkGray; return }
    $w = 118; try { $w = [math]::Max(100, [Console]::WindowWidth - 1) } catch {}
    ($objs | Format-Table -Property $cols -AutoSize -Wrap | Out-String -Width $w).TrimEnd() | Write-Host
}
function Sev-Color($s) { switch ($s) { 'High' { 'Red' } 'Medium' { 'Yellow' } 'Low' { 'Cyan' } default { 'Gray' } } }
function Out-Color($o) { switch ($o) { 'SAFE CANDIDATE' { 'Green' } 'PROTECTED' { 'Magenta' } default { 'Yellow' } } }

# ------------------------------------------------------------ logging/config
function Write-Log($Level, $Msg) {
    try { Add-Content -Path $Script:LogFile -Value ("{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Msg) -Encoding UTF8 } catch {}
}
function Write-EventRec($Type, $Detail) {
    $o = [pscustomobject]@{ Time = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); Session = $Script:SessionId; Type = $Type; Detail = $Detail }
    try { $o | Export-Csv -Path $Script:EventsCsv -Append -NoTypeInformation -Encoding UTF8 } catch {}
    Write-Log 'EVENT' ("{0} | {1}" -f $Type, $Detail)
}
function Load-Cfg {
    if (Test-Path $Script:CfgPath) {
        try {
            $j = Get-Content $Script:CfgPath -Raw | ConvertFrom-Json
            foreach ($p in $j.PSObject.Properties) { if ($Script:Cfg.Contains($p.Name)) { $Script:Cfg[$p.Name] = $p.Value } }
        } catch {}
    }
}
function Save-Cfg { try { $Script:Cfg | ConvertTo-Json | Set-Content -Path $Script:CfgPath -Encoding UTF8 } catch {} }
function Invoke-Retention {
    # Only NetWatch's own old logs/reports are removed, per the configured retention.
    $cut = (Get-Date).AddDays(-[int]$Script:Cfg.RetentionDays)
    foreach ($d in @($Script:Dirs.Logs, $Script:Dirs.Reports)) {
        Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $cut -and $_.Name -ne 'events.csv' } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $Script:EventsCsv) {
        $f = Get-Item $Script:EventsCsv
        if ($f.Length -gt ([int]$Script:Cfg.MaxLogMB * 1MB)) {
            try {
                $rows = @(Import-Csv $Script:EventsCsv)
                $rows | Select-Object -Last ([int]($rows.Count / 2)) | Export-Csv $Script:EventsCsv -NoTypeInformation -Encoding UTF8
                Write-Log 'INFO' 'events.csv trimmed to half (size limit)'
            } catch {}
        }
    }
}
function Redact-Cmd([string]$s) {
    if (-not $s) { return $s }
    return ($s -replace '(?i)(token|key|secret|password|passwd|pwd|auth|sig|session)=[^\s&"]+', '$1=<redacted>')
}

# ------------------------------------------------------- process / signature
function Get-Sig($path) {
    if (-not $path -or -not (Test-Path -LiteralPath $path)) { return [pscustomobject]@{ Status = 'PathUnavailable'; Publisher = '' } }
    if ($Script:SigCache.ContainsKey($path)) { return $Script:SigCache[$path] }
    $r = try {
        $s = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        $pub = ''
        if ($s.SignerCertificate) { $pub = ($s.SignerCertificate.Subject -replace '^.*?CN=', '' -replace ',.*$', '' -replace '"', '') }
        [pscustomobject]@{ Status = [string]$s.Status; Publisher = $pub }
    } catch { [pscustomobject]@{ Status = 'Error'; Publisher = '' } }
    $Script:SigCache[$path] = $r
    return $r
}
function Get-ProcTable {
    $t = @{}
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object { $t[[int]$_.ProcessId] = $_ }
    return $t
}
function Get-SvcMap {
    $m = @{}
    Get-CimInstance Win32_Service -Filter "State='Running'" -ErrorAction SilentlyContinue | ForEach-Object {
        $id = [int]$_.ProcessId
        if ($id -gt 0) { if (-not $m.ContainsKey($id)) { $m[$id] = New-Object System.Collections.ArrayList }; [void]$m[$id].Add($_.Name) }
    }
    return $m
}
function Get-Categ($name, $path) {
    $n = "$name $path"
    if ($n -match '(?i)MoUsoCoreWorker|TiWorker|usocoreworker|WaaSMedic|SIHClient|musnotification|GoogleUpdate|MicrosoftEdgeUpdate|updater|DeliveryOptimization|wuauclt') { return 'Update service' }
    if ($n -match '(?i)chrome|msedge|firefox|brave|opera|vivaldi|iexplore') { return 'Browser' }
    if ($n -match '(?i)onedrive|dropbox|googledrivefs|google drive|icloud|\\box\\|megasync|syncthing') { return 'Cloud sync' }
    if ($n -match '(?i)steam|epicgames|battle\.net|ubisoft|upc\.exe|galaxyclient|riotclient|origin|eaapp|xbox|gamingservices') { return 'Game launcher' }
    if ($n -match '(?i)spotify|netflix|vlc|plex|obs64|twitch|zoom|teams|skype|discord|youtube') { return 'Streaming/communication' }
    if ($n -match '(?i)backblaze|acronis|veeam|crashplan|duplicati|carbonite') { return 'Backup' }
    if ($n -match '(?i)qbittorrent|utorrent|bittorrent|transmission|deluge|emule|vuze') { return 'Peer-to-peer' }
    if ($n -match '(?i)idman|freedownload|fdm\.exe|jdownloader|aria2|downloader') { return 'Download manager' }
    if ($path -and $path.StartsWith($env:windir, [StringComparison]::OrdinalIgnoreCase)) { return 'Windows component (by path)' }
    return 'Other/unknown'
}
function Test-UserWritablePath($p) {
    if (-not $p) { return $false }
    $pats = @($env:TEMP, "$env:LOCALAPPDATA\Temp", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", $env:APPDATA, $env:LOCALAPPDATA, $env:PUBLIC, $env:ProgramData)
    foreach ($x in $pats) { if ($x -and $p.StartsWith($x, [StringComparison]::OrdinalIgnoreCase)) { return $true } }
    return $false
}
function Get-AvPaths {
    if ($null -eq $Script:AvPaths) {
        $Script:AvPaths = @()
        try {
            $Script:AvPaths = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
                ForEach-Object { $_.pathToSignedProductExe; $_.pathToSignedReportingExe } |
                Where-Object { $_ } | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_).ToLower() })
        } catch {}
    }
    return $Script:AvPaths
}

# --------------------------------------------- Module I: classification core
function New-Cls($o, $ev, $ck, $lm) { return [pscustomobject]@{ Outcome = $o; Evidence = @($ev); Checks = @($ck); Limitations = @($lm) } }
function Save-Cls($kind, $name, $path, $cls) {
    $key = "{0}|{1}|{2}" -f $kind, $name, $path
    $prevO = $Script:ClsLast[$key]
    if ($prevO -eq $cls.Outcome) { return }
    $note = ''
    if ($prevO) { $note = "RECLASSIFIED from $prevO" }
    $rec = [pscustomobject]@{ Time = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); Kind = $kind; Name = $name; Path = $path; Outcome = $cls.Outcome; Reason = ($cls.Evidence -join '; '); Checks = ($cls.Checks -join '; '); Limitations = ($cls.Limitations -join '; '); Note = $note }
    try { Add-Content -Path $Script:ClsFile -Value ($rec | ConvertTo-Json -Compress) -Encoding UTF8 } catch {}
    $Script:ClsLast[$key] = $cls.Outcome
    [void]$Script:SessionCls.Add($rec)
}
function Load-ClsHistory {
    if (Test-Path $Script:ClsFile) {
        foreach ($l in (Get-Content $Script:ClsFile -ErrorAction SilentlyContinue)) {
            try { $r = $l | ConvertFrom-Json; $Script:ClsLast[("{0}|{1}|{2}" -f $r.Kind, $r.Name, $r.Path)] = $r.Outcome } catch {}
        }
    }
}
function Get-Classification {
    param([string]$Path, [string]$Kind = 'Process', [string]$Name = '', [int]$OtherRefs = -1)
    $ev = @(); $ck = @(); $lm = @()
    if (-not $Path) {
        $ck += 'Executable path lookup: FAILED (no path or access denied)'
        if ($Name -in @('System', 'Registry', 'Memory Compression', 'Secure System', 'System Idle Process', 'Idle')) {
            $ev += 'No image path: kernel-level pseudo process'
            $lm += 'Identified by name because such processes have no image file'
            $c = New-Cls 'PROTECTED' $ev $ck $lm
        } else {
            $ev += 'Executable path unavailable'
            $lm += 'Missing information is never treated as proof of safety. Run elevated for deeper access.'
            $c = New-Cls 'NEEDS REVIEW' $ev $ck $lm
        }
        Save-Cls $Kind $Name $Path $c; return $c
    }
    $ck += 'Executable path obtained'
    if (-not (Test-Path -LiteralPath $Path)) {
        $ev += "Target file not found: $Path"; $ck += 'File existence check: NOT FOUND'
        if ($Kind -eq 'Startup' -and $OtherRefs -eq 0) {
            $ck += 'Cross-reference against other startup entries, tasks and services: no other reference to this path'
            $lm += 'Other installers or application settings outside the scanned locations could still reference this path'
            $c = New-Cls 'SAFE CANDIDATE' $ev $ck $lm
        } else {
            $lm += 'Cross-reference not conclusive; entry may be re-created by its application'
            $c = New-Cls 'NEEDS REVIEW' $ev $ck $lm
        }
        Save-Cls $Kind $Name $Path $c; return $c
    }
    $sg = Get-Sig $Path
    $ck += "Authenticode signature checked: $($sg.Status)"
    $inWin = $Path.StartsWith($env:windir, [StringComparison]::OrdinalIgnoreCase)
    $msSig = ($sg.Status -eq 'Valid' -and $sg.Publisher -match '^Microsoft')
    $ev += "Signature: $($sg.Status) $($sg.Publisher)"
    if ($inWin -and $msSig) {
        $ev += 'Located under the Windows directory and validly signed by Microsoft'
        $c = New-Cls 'PROTECTED' $ev $ck @('Name/path based component identification; a Microsoft-signed file can still be misused, but is not eligible for routine cleanup')
    } elseif ((Get-AvPaths) -contains $Path.ToLower() -or ($sg.Status -eq 'Valid' -and $Path -match '(?i)\\(Windows Defender|Microsoft Defender|Windows Security)\\')) {
        $ev += 'Registered security product / Windows Security component'
        $c = New-Cls 'PROTECTED' $ev $ck @('Security software must not be subjected to routine cleanup')
    } else {
        $wr = Test-UserWritablePath $Path
        if ($wr) { $ev += 'Located in a user-writable location (also common for legitimate per-user apps)' }
        if ($sg.Status -ne 'Valid') { $ev += 'Not validly signed (unsigned software is common and not proof of malice)' }
        $lm += 'Dependency analysis (other apps or services relying on this item) was not performed'
        $lm += 'Reputation lookup intentionally not performed (nothing is sent to external services)'
        $c = New-Cls 'NEEDS REVIEW' $ev $ck $lm
    }
    Save-Cls $Kind $Name $Path $c
    return $c
}
function Show-Cls($c) {
    Say (" Outcome   : {0}" -f $c.Outcome) (Out-Color $c.Outcome)
    foreach ($e in $c.Evidence) { Say ("   evidence  : {0}" -f $e) }
    foreach ($e in $c.Checks) { Say ("   check     : {0}" -f $e) DarkGray }
    foreach ($e in $c.Limitations) { Say ("   limitation: {0}" -f $e) DarkYellow }
}

# --------------------------------------------------------------- findings
function Add-Finding {
    param($Module, $Title, $Evidence, $Severity = 'Low', $Cause = '', $Confidence = 'Low', $Next = '', $Repair = 'None', $Status = 'Suspected', $Outcome = 'NEEDS REVIEW')
    $old = @($Script:Findings | Where-Object { $_.Module -eq $Module -and $_.Title -eq $Title })
    foreach ($o in $old) { $Script:Findings.Remove($o) }
    [void]$Script:Findings.Add([pscustomobject]@{ Time = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); Module = $Module; Title = $Title; Evidence = $Evidence; Severity = $Severity; Cause = $Cause; Confidence = $Confidence; NextStep = $Next; RepairOptions = $Repair; Status = $Status; Outcome = $Outcome })
    Write-Log 'FINDING' ("{0} | {1} | {2} | {3}" -f $Module, $Title, $Severity, $Status)
}
function Show-Findings($Module) {
    $f = @($Script:Findings | Where-Object { $_.Module -eq $Module })
    Say ''
    if ($f.Count -eq 0) { Say " No findings recorded for this check ($Module)." Green; return }
    foreach ($x in ($f | Sort-Object @{e = { switch ($_.Severity) { 'High' { 0 } 'Medium' { 1 } default { 2 } } } })) {
        Say (" [{0}] {1}   ({2}, confidence: {3})" -f $x.Severity.ToUpper(), $x.Title, $x.Status, $x.Confidence) (Sev-Color $x.Severity)
        Say ("      Evidence : {0}  @ {1}" -f $x.Evidence, $x.Time)
        if ($x.Cause) { Say ("      Possible cause: {0}" -f $x.Cause) }
        if ($x.NextStep) { Say ("      Next diagnostic step: {0}" -f $x.NextStep) }
        Say ("      Repair options: {0}   | Classification: {1}" -f $x.RepairOptions, $x.Outcome) DarkGray
    }
}

# ------------------------------------------------------------ net primitives
function Test-Ping($h, $ms = 1500) {
    try { $p = New-Object Net.NetworkInformation.Ping; $r = $p.Send($h, $ms); if ($r.Status -eq 'Success') { return [int]$r.RoundtripTime } else { return -1 } } catch { return -1 }
}
function Test-Tcp($h, $port, $ms = 2000) {
    $c = $null
    try {
        $c = New-Object Net.Sockets.TcpClient
        $ar = $c.BeginConnect($h, $port, $null, $null)
        $ok = $ar.AsyncWaitHandle.WaitOne($ms, $false)
        if ($ok) { try { $c.EndConnect($ar) } catch { $ok = $false } }
        return $ok
    } catch { return $false } finally { if ($c) { $c.Close() } }
}
function Measure-Dns($name, $server) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        if ($server) { [void](Resolve-DnsName $name -Server $server -Type A -DnsOnly -QuickTimeout -ErrorAction Stop) }
        else { [void](Resolve-DnsName $name -Type A -DnsOnly -QuickTimeout -ErrorAction Stop) }
        $sw.Stop(); return [pscustomobject]@{ Ok = $true; Ms = [int]$sw.ElapsedMilliseconds }
    } catch { $sw.Stop(); return [pscustomobject]@{ Ok = $false; Ms = [int]$sw.ElapsedMilliseconds } }
}
function Get-PingStats($h, $n = 10) {
    $v = @(); $lost = 0
    for ($i = 0; $i -lt $n; $i++) { $m = Test-Ping $h 1500; if ($m -lt 0) { $lost++ } else { $v += $m }; Start-Sleep -Milliseconds 250 }
    $avg = 0; $max = 0; $jit = 0
    if ($v.Count -gt 0) {
        $avg = [math]::Round(($v | Measure-Object -Average).Average, 1); $max = ($v | Measure-Object -Maximum).Maximum
        if ($v.Count -gt 1) { $d = @(); for ($i = 1; $i -lt $v.Count; $i++) { $d += [math]::Abs($v[$i] - $v[$i - 1]) }; $jit = [math]::Round(($d | Measure-Object -Average).Average, 1) }
    }
    return [pscustomobject]@{ Host = $h; Sent = $n; LossPct = [math]::Round(100 * $lost / $n, 0); AvgMs = $avg; MaxMs = $max; JitterMs = $jit }
}
function Get-LevelText($l) {
    switch ($l) {
        'ONLINE' { 'Internet access confirmed (gateway, external IP, DNS and web TCP all work)' }
        'NO-LINK' { 'No active adapter with a default gateway' }
        'NO-GATEWAY' { 'Adapter is up but the gateway did not answer and no external host was reachable (Wi-Fi/router/cable problem)' }
        'NO-EXTERNAL' { 'Gateway answers but external hosts are unreachable (router uplink / ISP / firewall)' }
        'DNS-FAIL' { 'External IP works but DNS lookups fail (DNS server / DNS settings)' }
        'WEB-TCP-FAIL' { 'DNS works but TCP to a web host failed (captive portal, proxy, firewall, or partial outage)' }
        default { $l }
    }
}
function Get-ConnState {
    $r = [ordered]@{ Adapter = ''; Kind = ''; Status = ''; Ip = ''; Gateway = ''; Dns = @(); GwMs = -2; ExtMs = -2; ExtTcp = $false; DnsOk = $false; DnsMs = -1; WebTcp = $false; Level = 'NO-LINK' }
    $cfg = $null
    try { $cfg = Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1 } catch {}
    if (-not $cfg) { $Script:LastLevel = 'NO-LINK'; return [pscustomobject]$r }
    $r.Adapter = [string]$cfg.InterfaceAlias
    $r.Status = [string]$cfg.NetAdapter.Status
    $d = [string]$cfg.NetAdapter.InterfaceDescription
    if ($d -match '(?i)wi-?fi|wireless|802\.11|wlan') { $r.Kind = 'Wi-Fi' } elseif ($d -match '(?i)vpn|tap-|wireguard|tunnel') { $r.Kind = 'VPN/tunnel' } else { $r.Kind = 'Ethernet/other' }
    try { $r.Ip = [string](@($cfg.IPv4Address)[0].IPAddress) } catch {}
    $r.Gateway = [string]$cfg.IPv4DefaultGateway.NextHop
    $r.Dns = @($cfg.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses })
    $r.GwMs = Test-Ping $r.Gateway 1500
    $r.ExtMs = Test-Ping '1.1.1.1' 1500
    if ($r.ExtMs -lt 0) { $r.ExtMs = Test-Ping '8.8.8.8' 1500 }
    $r.ExtTcp = Test-Tcp '1.1.1.1' 443 2000
    $srv = $null; if ($r.Dns.Count -gt 0) { $srv = $r.Dns[0] }
    $dm = Measure-Dns 'www.msftconnecttest.com' $srv
    $r.DnsOk = $dm.Ok; $r.DnsMs = $dm.Ms
    $r.WebTcp = Test-Tcp 'www.msftconnecttest.com' 80 2500
    $ext = ($r.ExtMs -ge 0 -or $r.ExtTcp)
    if (-not $ext) { if ($r.GwMs -lt 0) { $r.Level = 'NO-GATEWAY' } else { $r.Level = 'NO-EXTERNAL' } }
    elseif (-not $r.DnsOk) { $r.Level = 'DNS-FAIL' }
    elseif (-not $r.WebTcp) { $r.Level = 'WEB-TCP-FAIL' }
    else { $r.Level = 'ONLINE' }
    $Script:LastLevel = $r.Level
    return [pscustomobject]$r
}
function Get-Spark($list, $n = 50) {
    $chars = ' .:-=+*#@'
    $v = @($list | Select-Object -Last $n)
    if ($v.Count -eq 0) { return '' }
    $mx = ($v | Measure-Object -Maximum).Maximum
    if ($mx -le 0) { return ('_' * $v.Count) }
    return (($v | ForEach-Object { $chars[[int][math]::Min(8, [math]::Floor($_ / $mx * 8.99))] }) -join '')
}

# ------------------------------------------- Modules A + D: live monitor
function Mon-Event($type, $detail) {
    $tag = ''
    if ($Script:OnlineAt -and ((Get-Date) - $Script:OnlineAt).TotalSeconds -lt 60 -and $type -in @('NEW_CONN', 'NEW_LISTEN', 'NEW_NETPROC')) { $tag = ' [within 60s of connection]' }
    Write-EventRec $type ($detail + $tag)
    $Script:Recent.Add(("{0} {1} {2}{3}" -f (Get-Date -Format 'HH:mm:ss'), $type, $detail, $tag))
    while ($Script:Recent.Count -gt 10) { $Script:Recent.RemoveAt(0) }
}
function Start-Monitor {
    $mtx = New-Object System.Threading.Mutex($false, 'Local\NetWatchMonitor_v1')
    $got = $false
    try { $got = $mtx.WaitOne(0) } catch {}
    if (-not $got) { Say ' Another NetWatch monitor is already running in this Windows session.' Yellow; Pause-Menu; return }
    try {
        $iv = [int]$Script:Cfg.IntervalSec; if ($iv -lt 1) { $iv = 2 }
        Write-EventRec 'MONITOR_START' ("interval={0}s elevated={1}" -f $iv, $Script:IsAdmin)
        Clear-Host
        $prev = @{}; $base = @{}; $adSt = @{}
        $peakDn = 0.0; $peakUp = 0.0
        $hDn = New-Object 'System.Collections.Generic.List[double]'
        $hUp = New-Object 'System.Collections.Generic.List[double]'
        $win = New-Object 'System.Collections.Generic.List[double]'
        $seenProc = @{}; $seenLis = @{}; $synCnt = @{}; $synLogged = @{}
        $level = '(testing...)'; $cs = $null; $cfgSig = ''; $tick = 0; $paused = $false; $adv = $false; $quit = $false
        $inBurst = $false; $baseline = $true
        $lastT = [DateTime]::UtcNow; $sumDn = 0.0; $sumUp = 0.0; $sessRx = 0.0; $sessTx = 0.0; $util = -1
        $rows = @(); $topConn = @(); $nEst = 0; $nLis = 0; $nNewProc = 0; $started = Get-Date
        while (-not $quit) {
            if (-not $paused) {
                $tick++
                $nowT = [DateTime]::UtcNow; $dt = ($nowT - $lastT).TotalSeconds; $lastT = $nowT
                $all = @(Get-NetAdapter -ErrorAction SilentlyContinue)
                $setChanged = $false
                foreach ($a in $all) {
                    $st = [string]$a.Status
                    if ($adSt.ContainsKey($a.Name) -and $adSt[$a.Name] -ne $st) { Mon-Event 'ADAPTER_STATE' ("{0}: {1} -> {2}" -f $a.Name, $adSt[$a.Name], $st); $setChanged = $true }
                    $adSt[$a.Name] = $st
                }
                $phys = @($all | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface })
                if ($phys.Count -eq 0) { $phys = @($all | Where-Object { $_.Status -eq 'Up' }) }
                $stats = @{}
                foreach ($s in @(Get-NetAdapterStatistics -ErrorAction SilentlyContinue)) { $stats[$s.Name] = $s }
                $sumDn = 0.0; $sumUp = 0.0; $sessRx = 0.0; $sessTx = 0.0; $rows = @(); $util = -1
                foreach ($a in $phys) {
                    $s = $stats[$a.Name]; if (-not $s) { continue }
                    $rx = [double]$s.ReceivedBytes; $tx = [double]$s.SentBytes
                    if (-not $base.ContainsKey($a.Name)) { $base[$a.Name] = @($rx, $tx) }
                    $dn = 0.0; $up = 0.0
                    if ($prev.ContainsKey($a.Name) -and $dt -gt 0) {
                        $d1 = $rx - $prev[$a.Name][0]; $d2 = $tx - $prev[$a.Name][1]
                        if ($d1 -ge 0) { $dn = $d1 / $dt }; if ($d2 -ge 0) { $up = $d2 / $dt }
                    }
                    $prev[$a.Name] = @($rx, $tx)
                    $link = 0.0; try { $link = [double]$a.ReceiveLinkSpeed } catch {}
                    $u = -1; if ($link -gt 0) { $u = [math]::Min(100, ([math]::Max($dn, $up) * 8 / $link * 100)) }
                    if ($u -gt $util) { $util = $u }
                    $sumDn += $dn; $sumUp += $up; $sessRx += ($rx - $base[$a.Name][0]); $sessTx += ($tx - $base[$a.Name][1])
                    $rows += [pscustomobject]@{ Name = $a.Name; Dn = $dn; Up = $up; Rx = $rx; Tx = $tx; Link = $link }
                }
                if ($tick -gt 1) {
                    if ($sumDn -gt $peakDn) { $peakDn = $sumDn }; if ($sumUp -gt $peakUp) { $peakUp = $sumUp }
                    $hDn.Add($sumDn); $hUp.Add($sumUp); if ($hDn.Count -gt 60) { $hDn.RemoveAt(0); $hUp.RemoveAt(0) }
                    $tot = $sumDn + $sumUp
                    if ($win.Count -ge 10) {
                        $avg = ($win | Measure-Object -Average).Average
                        $thr = [math]::Max([double]$Script:Cfg.BurstMBps * 1MB, $avg * [double]$Script:Cfg.BurstFactor)
                        if ($tot -gt $thr) {
                            if (-not $inBurst) {
                                $inBurst = $true
                                $dir = 'download'; if ($sumUp -gt $sumDn) { $dir = 'UPLOAD' }
                                Mon-Event 'BURST' ("{0} burst: down {1}, up {2} (recent avg {3}). Adapter counters cannot name the process - use menu 4." -f $dir, (Fmt-Rate $sumDn), (Fmt-Rate $sumUp), (Fmt-Rate $avg))
                            }
                        } else { $inBurst = $false }
                    }
                    $win.Add($tot); if ($win.Count -gt 30) { $win.RemoveAt(0) }
                }
                # connections and processes
                $tcp = @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
                $procs = @{}
                foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) { $procs[$p.Id] = $p }
                if ($seenProc.Count -gt 20000) { $seenProc = @{} }
                $logged = 0
                foreach ($p in $procs.Values) {
                    $stt = $null; try { $stt = $p.StartTime.Ticks } catch {}
                    $k = "{0}|{1}" -f $p.Id, $stt
                    if (-not $seenProc.ContainsKey($k)) {
                        $seenProc[$k] = $true
                        if (-not $baseline) { $nNewProc++; if ($logged -lt 20) { Write-EventRec 'NEW_PROC' ("{0} pid={1}" -f $p.ProcessName, $p.Id); $logged++ } }
                    }
                }
                $est = @($tcp | Where-Object { [string]$_.State -eq 'Established' -and $_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0)' })
                $nEst = $est.Count
                if ($Script:Seen.Count -gt 5000) { $Script:Seen = @{} }
                $now2 = Get-Date
                foreach ($c in $est) {
                    $pn = "pid $($c.OwningProcess)"; if ($procs.ContainsKey([int]$c.OwningProcess)) { $pn = $procs[[int]$c.OwningProcess].ProcessName }
                    $k = "{0}|{1}|{2}" -f $c.OwningProcess, $c.RemoteAddress, $c.RemotePort
                    if (-not $Script:Seen.ContainsKey($k)) {
                        $Script:Seen[$k] = @{ First = $now2; Last = $now2; Name = $pn }
                        if (-not $baseline) {
                            Mon-Event 'NEW_CONN' ("{0} (pid {1}) -> {2}:{3}" -f $pn, $c.OwningProcess, $c.RemoteAddress, $c.RemotePort)
                        }
                    } else { $Script:Seen[$k].Last = $now2 }
                }
                $lis = @($tcp | Where-Object { [string]$_.State -eq 'Listen' })
                $nLis = $lis.Count
                foreach ($c in $lis) {
                    $k = "{0}|{1}" -f $c.LocalPort, $c.OwningProcess
                    if (-not $seenLis.ContainsKey($k)) {
                        $seenLis[$k] = $true
                        if (-not $baseline) {
                            $pn = "pid $($c.OwningProcess)"; if ($procs.ContainsKey([int]$c.OwningProcess)) { $pn = $procs[[int]$c.OwningProcess].ProcessName }
                            Mon-Event 'NEW_LISTEN' ("{0} (pid {1}) listening on {2}:{3}" -f $pn, $c.OwningProcess, $c.LocalAddress, $c.LocalPort)
                        }
                    }
                }
                $syn = @($tcp | Where-Object { [string]$_.State -eq 'SynSent' })
                $curSyn = @{}
                foreach ($c in $syn) {
                    $k = "{0}|{1}|{2}" -f $c.OwningProcess, $c.RemoteAddress, $c.RemotePort
                    $curSyn[$k] = $true
                    if ($synCnt.ContainsKey($k)) { $synCnt[$k]++ } else { $synCnt[$k] = 1 }
                    if ($synCnt[$k] -ge 3 -and -not $synLogged.ContainsKey($k)) {
                        $synLogged[$k] = $true
                        $pn = "pid $($c.OwningProcess)"; if ($procs.ContainsKey([int]$c.OwningProcess)) { $pn = $procs[[int]$c.OwningProcess].ProcessName }
                        Mon-Event 'CONN_FAIL_REPEAT' ("{0} repeatedly attempting {1}:{2} (no handshake across {3} samples)" -f $pn, $c.RemoteAddress, $c.RemotePort, $synCnt[$k])
                    }
                }
                foreach ($k in @($synCnt.Keys)) { if (-not $curSyn.ContainsKey($k)) { $synCnt.Remove($k); $synLogged.Remove($k) } }
                $topConn = @($est | Group-Object OwningProcess | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object {
                        $id = [int]$_.Name; $pp = $null; if ($procs.ContainsKey($id)) { $pp = $procs[$id] }
                        $nm = "pid $id"; $pth = ''
                        if ($pp) { $nm = $pp.ProcessName; try { $pth = $pp.Path } catch {} }
                        [pscustomobject]@{ Name = $nm; Id = $id; Count = $_.Count; Path = $pth }
                    })
                foreach ($grp in ($est | Group-Object OwningProcess)) {
                    $k = "net|$($grp.Name)"
                    if (-not $seenProc.ContainsKey($k)) {
                        $seenProc[$k] = $true
                        if (-not $baseline) {
                            $nid = [int]$grp.Name; $nn = "pid $nid"; $np = ''
                            if ($procs.ContainsKey($nid)) { $nn = $procs[$nid].ProcessName; try { $np = $procs[$nid].Path } catch {} }
                            Mon-Event 'NEW_NETPROC' ("{0} (pid {1}) began communicating externally, path={2}" -f $nn, $nid, $np)
                        }
                    }
                }
                # connectivity levels, config changes
                if ($tick -eq 1 -or $setChanged -or (($tick % [int]$Script:Cfg.ConnectivityEveryTicks) -eq 0)) {
                    $cs = Get-ConnState
                    $sig = "{0}|{1}|{2}|{3}" -f $cs.Adapter, $cs.Ip, $cs.Gateway, ($cs.Dns -join ',')
                    if ($cfgSig -and $sig -ne $cfgSig) { Mon-Event 'CONFIG_CHANGE' ("adapter|ip|gateway|dns changed to {0}" -f $sig) }
                    $cfgSig = $sig
                    if ($cs.Level -ne $level) {
                        $det = "{0} (adapter={1} [{2}] status={3} ip={4} gw={5} dns={6} gwPing={7}ms extPing={8}ms dnsTime={9}ms)" -f $cs.Level, $cs.Adapter, $cs.Kind, $cs.Status, $cs.Ip, $cs.Gateway, ($cs.Dns -join ','), $cs.GwMs, $cs.ExtMs, $cs.DnsMs
                        if ($level -eq '(testing...)') { Write-EventRec 'CONNECTIVITY' ("initial: " + $det) } else { Mon-Event 'CONNECTIVITY' ("{0} -> {1}" -f $level, $det) }
                        if ($cs.Level -eq 'ONLINE' -and $level -ne '(testing...)') { $Script:OnlineAt = Get-Date }
                        $level = $cs.Level
                    }
                }
                $baseline = $false
            }
            # ---- render
            $w = 110; try { $w = [Console]::WindowWidth - 1 } catch {}
            $L = New-Object System.Collections.ArrayList
            $state = 'RUNNING'; if ($paused) { $state = 'PAUSED' }
            [void]$L.Add(@(("NETWATCH LIVE MONITOR   [P]ause/resume  [A]dvanced  [R]eset peaks  [Q]uit   interval {0}s   {1}   {2}" -f $iv, $state, (Get-Date -Format 'HH:mm:ss')), 'Cyan'))
            $lc = 'Yellow'; if ($level -eq 'ONLINE') { $lc = 'Green' } elseif ($level -match 'NO-') { $lc = 'Red' }
            $adn = ''; if ($cs) { $adn = "{0} [{1}] ip {2} gw {3} dns {4}" -f $cs.Adapter, $cs.Kind, $cs.Ip, $cs.Gateway, ($cs.Dns -join ',') }
            [void]$L.Add(@(("Connectivity: {0}  {1}" -f $level, $adn), $lc))
            [void]$L.Add(@((Get-LevelText $level), 'DarkGray'))
            [void]$L.Add(@('', 'Gray'))
            [void]$L.Add(@('ADAPTER TRAFFIC - DIRECTLY MEASURED (Windows adapter counters, physical adapters that are Up)', 'White'))
            if ($tick -le 1) {
                [void]$L.Add(@('  Collecting first sample... rates appear after the second sample.', 'DarkGray'))
            } else {
                [void]$L.Add(@(("  Download : {0,-14} ({1:N1} Mbps)   peak {2}" -f (Fmt-Rate $sumDn), ($sumDn * 8 / 1e6), (Fmt-Rate $peakDn)), 'Green'))
                [void]$L.Add(@(("  Upload   : {0,-14} ({1:N1} Mbps)   peak {2}" -f (Fmt-Rate $sumUp), ($sumUp * 8 / 1e6), (Fmt-Rate $peakUp)), 'Yellow'))
                $us = 'n/a (link speed unknown)'; if ($util -ge 0) { $us = ('{0:N1}% of link speed' -f $util) }
                [void]$L.Add(@(("  Utilization: {0}" -f $us), 'Gray'))
                [void]$L.Add(@(("  DL history : [{0}]" -f (Get-Spark $hDn)), 'DarkGreen'))
                [void]$L.Add(@(("  UL history : [{0}]" -f (Get-Spark $hUp)), 'DarkYellow'))
            }
            [void]$L.Add(@(("  Since monitor start: received {0}, sent {1}" -f (Fmt-Bytes $sessRx), (Fmt-Bytes $sessTx)), 'Gray'))
            if ($adv) { foreach ($r in $rows) { [void]$L.Add(@(("    {0,-26} down {1,-12} up {2,-12} total rx {3} / tx {4}" -f $r.Name, (Fmt-Rate $r.Dn), (Fmt-Rate $r.Up), (Fmt-Bytes $r.Rx), (Fmt-Bytes $r.Tx)), 'DarkGray')) } }
            [void]$L.Add(@('', 'Gray'))
            [void]$L.Add(@(("EXTERNAL TCP CONNECTIONS: {0} established, {1} listening ports, {2} new processes seen" -f $nEst, $nLis, $nNewProc), 'White'))
            [void]$L.Add(@('  Counts per process = INDICATOR ONLY, not bandwidth. Per-process bytes: menu 4 (admin).', 'DarkYellow'))
            foreach ($tc in $topConn) {
                $x = "  {0,-28} pid {1,-7} connections: {2}" -f $tc.Name, $tc.Id, $tc.Count
                if ($adv) { $x += "  " + $tc.Path }
                [void]$L.Add(@($x, 'Gray'))
            }
            [void]$L.Add(@('', 'Gray'))
            [void]$L.Add(@('RECENT EVENTS (all logged to events.csv)', 'White'))
            foreach ($e in $Script:Recent) { [void]$L.Add(@(("  " + $e), 'DarkCyan')) }
            try { [Console]::SetCursorPosition(0, 0) } catch { Clear-Host }
            $maxL = 44; try { $maxL = [Console]::WindowHeight - 1 } catch {}
            $n = 0
            foreach ($e in $L) {
                if ($n -ge $maxL) { break }
                $t = [string]$e[0]; if ($t.Length -gt $w) { $t = $t.Substring(0, $w) }
                Write-Host $t.PadRight($w) -ForegroundColor $e[1]; $n++
            }
            while ($n -lt $maxL -and $n -lt 46) { Write-Host (' ' * $w); $n++ }
            # ---- wait with key handling
            $end = (Get-Date).AddSeconds($iv)
            while ((Get-Date) -lt $end -and -not $quit) {
                try {
                    while ([Console]::KeyAvailable) {
                        $key = [Console]::ReadKey($true)
                        switch ($key.Key.ToString()) {
                            'Q' { $quit = $true }
                            'P' { $paused = -not $paused; if (-not $paused) { $prev = @{}; $lastT = [DateTime]::UtcNow; $tick = 0 } }
                            'A' { $adv = -not $adv; Clear-Host }
                            'R' { $peakDn = 0.0; $peakUp = 0.0 }
                        }
                    }
                } catch {}
                Start-Sleep -Milliseconds 100
            }
        }
        Write-EventRec 'MONITOR_STOP' ("duration={0:N0}s received={1} sent={2}" -f ((Get-Date) - $started).TotalSeconds, (Fmt-Bytes $sessRx), (Fmt-Bytes $sessTx))
    } finally {
        try { $mtx.ReleaseMutex() } catch {}
        $mtx.Dispose()
    }
    Clear-Host
}
function Show-LiveMenu {
    while ($true) {
        Head 'LIVE INTERNET ACTIVITY MONITOR'
        Say ' Monitoring is read-only and runs only while this window is open (no service, no scheduled task, no persistence).' DarkGray
        Say ''
        Say ' [1] Start live monitor (continuous; press Q to stop, P to pause, A for advanced view)'
        Say ' [2] Manual connectivity check (one-time, layered: adapter > gateway > external IP > DNS > web)'
        Say (' [3] Change polling interval (current {0}s: choose 1, 2, 5 or 10)' -f $Script:Cfg.IntervalSec)
        Say ' [B] Back'
        $c = (Read-Host ' Select').Trim().ToUpper()
        switch ($c) {
            '1' { Start-Monitor }
            '2' {
                Say ' Testing...' DarkGray
                $s = Get-ConnState
                Say ''
                Say (" Adapter  : {0} [{1}] status {2}" -f $s.Adapter, $s.Kind, $s.Status)
                Say (" IP / GW  : {0} / {1}   DNS: {2}" -f $s.Ip, $s.Gateway, ($s.Dns -join ', '))
                Say (" Gateway ping : {0}" -f $(if ($s.GwMs -ge 0) { "$($s.GwMs) ms" } else { 'no reply (some routers ignore ICMP)' }))
                Say (" External IP  : ping {0}; TCP 1.1.1.1:443 {1}" -f $(if ($s.ExtMs -ge 0) { "$($s.ExtMs) ms" } else { 'no reply' }), $(if ($s.ExtTcp) { 'OK' } else { 'failed' }))
                Say (" DNS lookup   : {0} ({1} ms)" -f $(if ($s.DnsOk) { 'OK' } else { 'FAILED' }), $s.DnsMs)
                Say (" Web TCP :80  : {0}" -f $(if ($s.WebTcp) { 'OK' } else { 'failed' }))
                Say (" RESULT: {0} - {1}" -f $s.Level, (Get-LevelText $s.Level)) $(if ($s.Level -eq 'ONLINE') { 'Green' } else { 'Yellow' })
                Write-EventRec 'MANUAL_CHECK' ("{0} adapter={1} ip={2} gw={3}" -f $s.Level, $s.Adapter, $s.Ip, $s.Gateway)
                Pause-Menu
            }
            '3' {
                $n = Ask-Int ' Interval seconds (1, 2, 5, 10)' 0
                if ($n -in 1, 2, 5, 10) { $Script:Cfg.IntervalSec = $n; Save-Cfg; Say ' Saved.' Green } else { Say ' Not changed (use 1, 2, 5 or 10).' Yellow }
                Start-Sleep -Seconds 1
            }
            'B' { return }
        }
    }
}

# --------------------------------------------- Module B: processes/connections
function Show-ProcDetail([int]$ProcId) {
    $cp = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcId" -ErrorAction SilentlyContinue
    if (-not $cp) { Say ' Process not found (it may have exited).' Yellow; return }
    Say ''
    Say (" Name      : {0}   PID {1}" -f $cp.Name, $ProcId) White
    Say (" Path      : {0}" -f $(if ($cp.ExecutablePath) { $cp.ExecutablePath } else { '(not accessible - run elevated)' }))
    $par = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f [int]$cp.ParentProcessId) -ErrorAction SilentlyContinue
    Say (" Parent    : {0} (PID {1})" -f $(if ($par) { $par.Name } else { 'exited or unknown' }), $cp.ParentProcessId)
    Say (" Started   : {0}" -f $cp.CreationDate)
    try { $o = Invoke-CimMethod -InputObject $cp -MethodName GetOwner -ErrorAction Stop; Say (" Owner     : {0}\{1}" -f $o.Domain, $o.User) } catch { Say ' Owner     : (not accessible)' }
    $sg = Get-Sig $cp.ExecutablePath
    Say (" Signature : {0}  Publisher: {1}" -f $sg.Status, $sg.Publisher)
    Say (" Category  : {0} (name/path hint only)" -f (Get-Categ $cp.Name $cp.ExecutablePath))
    $gp = Get-Process -Id $ProcId -ErrorAction SilentlyContinue
    if ($gp) {
        $cpu = ''; try { $cpu = ('{0:N1}s total CPU time' -f $gp.TotalProcessorTime.TotalSeconds) } catch { $cpu = 'CPU time not accessible' }
        Say (" Resources : {0}; working set {1}; {2} threads; {3} handles" -f $cpu, (Fmt-Bytes $gp.WorkingSet64), $gp.Threads.Count, $gp.HandleCount)
    }
    if ($cp.CommandLine) { $cl = Redact-Cmd $cp.CommandLine; if ($cl.Length -gt 220) { $cl = $cl.Substring(0, 220) + '...' }; Say (" Cmdline   : {0}   (shown on screen only, never logged)" -f $cl) DarkGray }
    $sv = Get-SvcMap
    if ($sv.ContainsKey($ProcId)) { Say (" Services hosted: {0}" -f ($sv[$ProcId] -join ', ')) }
    $cn = @(Get-NetTCPConnection -OwningProcess $ProcId -ErrorAction SilentlyContinue)
    Say (" TCP connections: {0}" -f $cn.Count)
    foreach ($c in ($cn | Select-Object -First 25)) {
        $k = "{0}|{1}|{2}" -f $ProcId, $c.RemoteAddress, $c.RemotePort
        $seen = ''
        if ($Script:Seen.ContainsKey($k)) { $seen = "  first seen {0:HH:mm:ss}, last seen {1:HH:mm:ss} (this session)" -f $Script:Seen[$k].First, $Script:Seen[$k].Last }
        Say ("   {0}:{1} -> {2}:{3}  {4}{5}" -f $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $c.RemotePort, $c.State, $seen) DarkGray
    }
    Say ''
    $cls = Get-Classification -Path $cp.ExecutablePath -Kind 'Process' -Name $cp.Name
    Show-Cls $cls
}
function Show-Connections {
    $adv = $false
    while ($true) {
        Head 'RUNNING PROCESSES AND NETWORK CONNECTIONS'
        Say (" View: {0}" -f $(if ($adv) { 'ADVANCED' } else { 'STANDARD' })) DarkGray
        Say ' [1] External established connections  [2] Also listening ports  [3] Process detail by PID  [A] Toggle advanced  [B] Back'
        $c = (Read-Host ' Select').Trim().ToUpper()
        if ($c -eq 'B') { return }
        if ($c -eq 'A') { $adv = -not $adv; continue }
        if ($c -eq '3') { $n = Ask-Int ' PID' -1; if ($n -ge 0) { Show-ProcDetail $n }; Pause-Menu; continue }
        if ($c -in '1', '2') {
            Say ' Collecting data and verifying signatures (first run can take a while)...' DarkGray
            $pt = Get-ProcTable; $svc = Get-SvcMap
            $tcp = @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
            if ($c -eq '1') { $sel = @($tcp | Where-Object { [string]$_.State -in 'Established', 'SynSent' -and $_.RemoteAddress -notmatch '^(127\.|::1$)' }) }
            else { $sel = @($tcp | Where-Object { [string]$_.State -in 'Established', 'SynSent', 'Listen' }) }
            $rows = foreach ($x in $sel) {
                $id = [int]$x.OwningProcess; $pr = $pt[$id]
                $path = $null; $nm = "pid $id"; $par = ''; $stt = ''
                if ($pr) { $path = $pr.ExecutablePath; $nm = $pr.Name; $stt = ([datetime]$pr.CreationDate).ToString('MM-dd HH:mm'); $pp = $pt[[int]$pr.ParentProcessId]; if ($pp) { $par = $pp.Name } else { $par = '(exited)' } }
                if ($nm -eq 'svchost.exe' -and $svc.ContainsKey($id)) { $nm = 'svchost[' + (($svc[$id] | Select-Object -First 2) -join ',') + ']' }
                $sg = Get-Sig $path
                $k = "{0}|{1}|{2}" -f $id, $x.RemoteAddress, $x.RemotePort
                $fs = '-'; if ($Script:Seen.ContainsKey($k)) { $fs = "{0:HH:mm:ss}/{1:HH:mm:ss}" -f $Script:Seen[$k].First, $Script:Seen[$k].Last }
                [pscustomobject]@{ Process = $nm; PID = $id; Remote = ("{0}:{1}" -f $x.RemoteAddress, $x.RemotePort); State = [string]$x.State; Signature = $sg.Status; Category = (Get-Categ $nm $path); Local = ("{0}:{1}" -f $x.LocalAddress, $x.LocalPort); Parent = $par; Started = $stt; Publisher = $sg.Publisher; FirstLast = $fs; Path = $path }
            }
            $rows = @($rows | Sort-Object Process, Remote)
            Say (" {0} rows. (UDP endpoints are not listed. 'Category' is a name/path hint, not proof.)" -f $rows.Count) DarkGray
            if ($adv) { Show-Table $rows @('Process', 'PID', 'Local', 'Remote', 'State', 'Signature', 'Publisher', 'Parent', 'Started', 'FirstLast', 'Category', 'Path') }
            else { Show-Table $rows @('Process', 'PID', 'Remote', 'State', 'Signature', 'Category') }
            Say ''
            $n = Read-Host ' Enter a PID for full detail, or press Enter'
            if ($n -match '^\d+$') { Show-ProcDetail ([int]$n); Pause-Menu }
        }
    }
}

# --------------------------------------------- Module C: startup investigation
function Get-ExePath([string]$cmd) {
    if (-not $cmd) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
    if ($c -match '^"([^"]+)"') { return $Matches[1] }
    if ($c -match '^(.+?\.(exe|bat|cmd|ps1|vbs|js|msi|scr|com|dll|lnk))(\s|$)') { return $Matches[1] }
    return ($c -split '\s+')[0]
}
function Get-NetPathCounts {
    $m = @{}; $cache = @{}
    foreach ($c in @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)) {
        if ($c.RemoteAddress -match '^(127\.|::1)') { continue }
        $id = [int]$c.OwningProcess
        if (-not $cache.ContainsKey($id)) { $pth = $null; $gp = Get-Process -Id $id -ErrorAction SilentlyContinue; if ($gp) { try { $pth = $gp.Path } catch {} }; $cache[$id] = $pth }
        $pp = $cache[$id]
        if ($pp) { $k = $pp.ToLower(); if ($m.ContainsKey($k)) { $m[$k]++ } else { $m[$k] = 1 } }
    }
    return $m
}
function Get-StartupEntries([switch]$Refresh) {
    if ($Script:StartupCache -and -not $Refresh) { return $Script:StartupCache }
    $list = New-Object System.Collections.ArrayList
    $add = { param($src, $name, $loc, $cmd, $trig, $state, $last, $reg, $kind)
        [void]$list.Add([pscustomobject]@{ Source = $src; Name = $name; Location = $loc; Command = (Redact-Cmd $cmd); Trigger = $trig; State = $state; LastRun = $last; RegPath = $reg; Kind = $kind })
    }
    $runKeys = @(
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM Run', 'At logon (all users)'),
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM RunOnce', 'Next logon, then removed'),
        @('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM Run (32-bit)', 'At logon (all users)'),
        @('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU Run', 'At logon (this user)'),
        @('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'HKCU RunOnce', 'Next logon, then removed'))
    foreach ($rk in $runKeys) {
        $k = Get-ItemProperty -Path $rk[0] -ErrorAction SilentlyContinue
        if (-not $k) { continue }
        $apv = $null
        if ($rk[1] -notmatch 'RunOnce') {
            $ap = 'Run'; if ($rk[1] -match '32-bit') { $ap = 'Run32' }
            $apv = Get-ItemProperty -Path ("{0}\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\{1}" -f $rk[0].Substring(0, 5), $ap) -ErrorAction SilentlyContinue
        }
        foreach ($pr in $k.PSObject.Properties) {
            if ($pr.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
            $st = 'Enabled'
            if ($apv -and $apv.PSObject.Properties[$pr.Name]) { $b = $apv.PSObject.Properties[$pr.Name].Value; if ($b -is [byte[]] -and ($b[0] -band 1)) { $st = 'Disabled (Task Manager)' } }
            & $add $rk[1] $pr.Name $rk[0] ([string]$pr.Value) $rk[2] $st '' $rk[0] 'Registry'
        }
    }
    $sf = @(@("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", 'Startup folder (user)'), @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", 'Startup folder (all users)'))
    $ws = $null; try { $ws = New-Object -ComObject WScript.Shell } catch {}
    foreach ($f in $sf) {
        Get-ChildItem -LiteralPath $f[0] -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
            $cmd = $_.FullName
            if ($_.Extension -eq '.lnk' -and $ws) { try { $l = $ws.CreateShortcut($_.FullName); $cmd = '"' + $l.TargetPath + '" ' + $l.Arguments } catch {} }
            & $add $f[1] $_.Name $f[0] $cmd 'At logon' 'Enabled' '' $null 'File'
        }
    }
    $msTasks = 0
    foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        if ($t.TaskPath -like '\Microsoft\*') { $msTasks++; continue }
        if ([string]$t.State -eq 'Disabled') { continue }
        $trg = (@($t.Triggers | ForEach-Object { ($_.CimClass.CimClassName -replace '^MSFT_Task', '' -replace 'Trigger$', '') }) -join ',')
        if (-not $trg) { $trg = 'Manual/other' }
        foreach ($a in @($t.Actions)) {
            if (-not $a.Execute) { continue }
            $last = ''
            try { $i = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop; if ($i.LastRunTime -gt [datetime]'2000-01-01') { $last = $i.LastRunTime.ToString('yyyy-MM-dd HH:mm') } else { $last = 'never' } } catch {}
            & $add 'Scheduled task' $t.TaskName $t.TaskPath ('"{0}" {1}' -f $a.Execute, $a.Arguments) $trg ([string]$t.State) $last $null 'Task'
        }
    }
    $svcWin = 0
    foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.StartMode -eq 'Auto' })) {
        $ex = Get-ExePath $s.PathName
        if ($ex -and $ex.StartsWith($env:windir, [StringComparison]::OrdinalIgnoreCase)) { $svcWin++; continue }
        $trig = 'Automatic at boot'; if ($s.DelayedAutoStart) { $trig = 'Automatic (delayed) after boot' }
        & $add 'Service' $s.Name ('Services\' + $s.DisplayName) $s.PathName $trig $s.State '' $null 'Service'
    }
    $netc = Get-NetPathCounts
    $res = foreach ($e in $list) {
        $path = Get-ExePath $e.Command
        $exists = [bool]($path -and (Test-Path -LiteralPath $path))
        $sg = Get-Sig $path
        $refs = 0
        if ($path) { $refs = @($list | Where-Object { $_ -ne $e -and (Get-ExePath $_.Command) -and ((Get-ExePath $_.Command).ToLower() -eq $path.ToLower()) }).Count }
        $concerns = New-Object System.Collections.ArrayList
        if (-not $exists) { [void]$concerns.Add('Target file not found (broken entry)') }
        elseif ($sg.Status -ne 'Valid') { [void]$concerns.Add("Signature: $($sg.Status)") }
        if ($exists -and (Test-UserWritablePath $path)) { [void]$concerns.Add('Runs from a user-writable location') }
        if ($e.Command -match '(?i)-enc(odedcommand)?\s|-w(indowstyle)?\s+hidden|FromBase64String|mshta|scrobj|\bhttps?://') { [void]$concerns.Add('Command pattern common in scripted/obfuscated launchers (indicator only)') }
        $net = 0; if ($path -and $netc.ContainsKey($path.ToLower())) { $net = $netc[$path.ToLower()] }
        $cls = Get-Classification -Path $path -Kind 'Startup' -Name $e.Name -OtherRefs $refs
        $rec = 'Review in Task Manager > Startup / Autoruns; verify the publisher; leave as is if you recognise it.'
        if (-not $exists) { $rec = 'Confirm the program was uninstalled; the stale entry can then be disabled (reversible) in the Repair Center.' }
        elseif ($concerns.Count -gt 0) { $rec = 'Verify where this came from (install date, publisher). Do not delete; compare against your installed programs first.' }
        [pscustomobject]@{ Source = $e.Source; Name = $e.Name; Location = $e.Location; Command = $e.Command; Path = $path; Trigger = $e.Trigger; State = $e.State; LastRun = $e.LastRun; Signature = $sg.Status; Publisher = $sg.Publisher; NetConns = $net; Concerns = ($concerns -join '; '); Outcome = $cls.Outcome; Cls = $cls; Recommendation = $rec; RegPath = $e.RegPath; Kind = $e.Kind }
    }
    $Script:StartupCache = @($res)
    Write-Log 'INFO' ("Startup scan: {0} entries, {1} Microsoft scheduled tasks and {2} Windows-directory services summarized only" -f $Script:StartupCache.Count, $msTasks, $svcWin)
    $Script:StartupMeta = "$msTasks tasks under \Microsoft\ and $svcWin auto-start services in the Windows directory were not listed individually."
    return $Script:StartupCache
}
function Show-Startup {
    while ($true) {
        Head 'STARTUP AND AUTOMATIC EXECUTION INVESTIGATION (read-only)'
        Say ' Scanning Run keys, Startup folders, scheduled tasks and auto-start services...' DarkGray
        $ents = Get-StartupEntries
        $i = 0
        $tbl = foreach ($e in $ents) { $i++; [pscustomobject]@{ '#' = $i; Source = $e.Source; Name = $e.Name; State = $e.State; Signature = $e.Signature; NetNow = $e.NetConns; Outcome = $e.Outcome; Concerns = $e.Concerns } }
        Show-Table $tbl @('#', 'Source', 'Name', 'State', 'Signature', 'NetNow', 'Outcome', 'Concerns')
        Say ("`n {0}" -f $Script:StartupMeta) DarkGray
        Say ' NetNow = external TCP connections open right now from that executable (correlation by executable path, not proof of cause).' DarkGray
        Say ' [number] Entry detail   [E] Export CSV   [R] Rescan   [B] Back'
        $c = (Read-Host ' Select').Trim().ToUpper()
        if ($c -eq 'B') { return }
        if ($c -eq 'R') { $Script:StartupCache = $null; continue }
        if ($c -eq 'E') {
            $f = Join-Path $Script:Dirs.Reports ("startup_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
            $ents | Select-Object Source, Name, Location, Command, Trigger, State, LastRun, Signature, Publisher, NetConns, Concerns, Outcome, Recommendation | Export-Csv $f -NoTypeInformation -Encoding UTF8
            Say " Saved: $f" Green; Say ' NOTE: contains local paths and command lines; review before sharing.' Yellow; Pause-Menu; continue
        }
        $n = 0
        if ([int]::TryParse($c, [ref]$n) -and $n -ge 1 -and $n -le $ents.Count) {
            $e = $ents[$n - 1]
            Say ''; Say (" {0}: {1}" -f $e.Source, $e.Name) White
            Say (" Location : {0}" -f $e.Location); Say (" Command  : {0}" -f $e.Command)
            Say (" Trigger  : {0}   State: {1}   Last run: {2}" -f $e.Trigger, $e.State, $(if ($e.LastRun) { $e.LastRun } else { 'not available' }))
            Say (" Signature: {0} {1}" -f $e.Signature, $e.Publisher)
            Say (" Related network activity now: {0} external connection(s)" -f $e.NetConns)
            Say (" Concerns : {0}" -f $(if ($e.Concerns) { $e.Concerns } else { 'none detected by the checks performed' }))
            Say (" Next step: {0}" -f $e.Recommendation)
            Show-Cls $e.Cls
            Pause-Menu
        }
    }
}

# ---------------------------------- Module D (per-process) via ETW capture
function Get-EvIp($v) {
    try {
        if ($v -is [Net.IPAddress]) { return $v }
        if ($v -is [byte[]]) { return (New-Object Net.IPAddress(, $v)) }
        return (New-Object Net.IPAddress([int64]$v))
    } catch { return $null }
}
function Get-AdapterTotals {
    $t = @{ Rx = 0.0; Tx = 0.0 }
    $ph = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $_.Name })
    foreach ($s in @(Get-NetAdapterStatistics -ErrorAction SilentlyContinue)) { if ($ph -contains $s.Name) { $t.Rx += [double]$s.ReceivedBytes; $t.Tx += [double]$s.SentBytes } }
    return $t
}
function Invoke-EtwCapture([int]$Seconds) {
    & logman stop $Script:EtwName -ets 2>&1 | Out-Null
    Remove-Item $Script:EtwFile -Force -ErrorAction SilentlyContinue
    $before = Get-ProcTable; $a0 = Get-AdapterTotals
    $o = & logman create trace $Script:EtwName -p 'Microsoft-Windows-Kernel-Network' 0x30 0xff -o $Script:EtwFile -ets 2>&1
    if ($LASTEXITCODE -ne 0) { Say ' Could not start the ETW session:' Red; $o | ForEach-Object { Say ("   $_") DarkGray }; return $null }
    $Script:EtwActive = $true
    Write-EventRec 'ETW_START' ("Kernel-Network trace for {0}s (user approved)" -f $Seconds)
    for ($i = $Seconds; $i -gt 0; $i--) { Write-Host ("`r Capturing... {0,3}s left (generate traffic now if you want to test)   " -f $i) -NoNewline -ForegroundColor Cyan; Start-Sleep -Seconds 1 }
    Write-Host ''
    & logman stop $Script:EtwName -ets 2>&1 | Out-Null
    $Script:EtwActive = $false
    $after = Get-ProcTable; $a1 = Get-AdapterTotals
    Say ' Parsing trace...' DarkGray
    $agg = @{}; $n = 0; $skipped = 0
    try {
        $evs = Get-WinEvent -FilterHashtable @{ Path = $Script:EtwFile; Id = 10, 11, 26, 27, 42, 43, 58, 59 } -Oldest -ErrorAction Stop
        foreach ($e in $evs) {
            $pr = $e.Properties
            if ($pr.Count -lt 3) { continue }
            if ($e.Id -in 10, 11, 42, 43) { $ip = Get-EvIp $pr[2].Value; if ($ip -and $ip.ToString().StartsWith('127.')) { $skipped++; continue } }
            if ($e.Id -in 26, 27, 58, 59) { $ip = Get-EvIp $pr[2].Value; if ($ip -and [Net.IPAddress]::IsLoopback($ip)) { $skipped++; continue } }
            $id = [int]$pr[0].Value; $sz = [double]$pr[1].Value
            if (-not $agg.ContainsKey($id)) { $agg[$id] = @{ Rx = 0.0; Tx = 0.0; Ev = 0 } }
            if ($e.Id -in 10, 26, 42, 58) { $agg[$id].Tx += $sz } else { $agg[$id].Rx += $sz }
            $agg[$id].Ev++; $n++
        }
    } catch {
        if ($_.Exception.Message -match 'No events were found') { Say ' No network events were captured in this window.' Yellow }
        else { Say (" Trace parsing failed: {0}" -f $_.Exception.Message) Red; return $null }
    }
    Remove-Item $Script:EtwFile -Force -ErrorAction SilentlyContinue
    $res = foreach ($id in $agg.Keys) {
        $nm = $null; $note = ''
        $b = $before[$id]; $a = $after[$id]
        if ($id -eq 4) { $nm = 'System (kernel/SMB/file sharing)'; $note = 'shared system process' }
        elseif ($b -and $a -and $b.CreationDate -ne $a.CreationDate) { $nm = "$($a.Name)?"; $note = 'PID reused during capture - attribution ambiguous' }
        elseif ($a) { $nm = $a.Name; $pth = $a.ExecutablePath }
        elseif ($b) { $nm = $b.Name; $note = 'exited during capture' }
        else { $nm = '(unknown)'; $note = 'short-lived process exited before it could be identified' }
        if ($nm -eq 'svchost.exe') { $note = ($note + ' shared service host: traffic may belong to any hosted service').Trim() }
        $pth2 = $null; if ($a) { $pth2 = $a.ExecutablePath } elseif ($b) { $pth2 = $b.ExecutablePath }
        [pscustomobject]@{ Process = $nm; PID = $id; Download = $agg[$id].Rx; Upload = $agg[$id].Tx; DnRate = ($agg[$id].Rx / $Seconds); UpRate = ($agg[$id].Tx / $Seconds); Category = (Get-Categ $nm $pth2); Note = $note }
    }
    $out = [pscustomobject]@{ Rows = @($res | Sort-Object { $_.Download + $_.Upload } -Descending); Seconds = $Seconds; AdRx = ($a1.Rx - $a0.Rx); AdTx = ($a1.Tx - $a0.Tx); Events = $n; Loopback = $skipped; Time = Get-Date }
    return $out
}
function Show-Bandwidth {
    Head 'PER-PROCESS BANDWIDTH INVESTIGATION'
    Say ' METHOD: Windows ETW provider Microsoft-Windows-Kernel-Network records TCP/UDP payload sizes per process ID.' DarkGray
    Say ' That is DIRECTLY MEASURED per-process traffic, but it needs Administrator rights and runs only during the capture you start.' DarkGray
    Say ' Adapter counters (what the live monitor shows) can NOT be split by process. Connection counts are NOT bandwidth.' DarkGray
    Say ''
    if (-not $Script:IsAdmin) {
        Say ' Per-process byte measurement is unavailable without Administrator rights.' Yellow
        Say ' What is still available now: connection-count INDICATORS (not bandwidth):' Yellow
        $pt = Get-ProcTable
        $rows = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1)' } | Group-Object OwningProcess | Sort-Object Count -Descending | Select-Object -First 12 | ForEach-Object {
                $p = $pt[[int]$_.Name]; $nm = "pid $($_.Name)"; $pth = $null; if ($p) { $nm = $p.Name; $pth = $p.ExecutablePath }
                [pscustomobject]@{ Process = $nm; PID = $_.Name; Connections = $_.Count; Category = (Get-Categ $nm $pth); Basis = 'connection-count indicator' } })
        Show-Table $rows @('Process', 'PID', 'Connections', 'Category', 'Basis')
        Say ''; Say ' Press E to relaunch NetWatch as Administrator (UAC prompt), or Enter to go back.' DarkGray
        if ((Read-Host ' ').Trim().ToUpper() -eq 'E') { Request-Elevation }
        return
    }
    Say ' Enabling this requires starting a temporary Windows trace session (read-only, no drivers or software installed).' Yellow
    Say ' Trace data stays on this PC, is parsed, then deleted; only per-process totals are kept.' Yellow
    if (-not (Confirm-Action ' Start a temporary ETW trace?')) { return }
    $sec = Ask-Int ' Capture duration in seconds (10-120) [20]' 20
    if ($sec -lt 10) { $sec = 10 }; if ($sec -gt 120) { $sec = 120 }
    $r = Invoke-EtwCapture $sec
    if (-not $r) { Pause-Menu; return }
    $Script:LastBw = $r
    $rows = $r.Rows | Select-Object -First 20 | ForEach-Object { [pscustomobject]@{ Process = $_.Process; PID = $_.PID; Download = (Fmt-Bytes $_.Download); Upload = (Fmt-Bytes $_.Upload); 'Avg down' = (Fmt-Rate $_.DnRate); 'Avg up' = (Fmt-Rate $_.UpRate); Category = $_.Category; Note = $_.Note } }
    Say ''; Say (" RESULTS over {0}s - DIRECTLY MEASURED per process (ETW payload bytes, {1} events, {2} loopback events skipped)" -f $r.Seconds, $r.Events, $r.Loopback) Green
    Show-Table $rows @('Process', 'PID', 'Download', 'Upload', 'Avg down', 'Avg up', 'Category', 'Note')
    $sRx = ($r.Rows | Measure-Object Download -Sum).Sum; $sTx = ($r.Rows | Measure-Object Upload -Sum).Sum
    Say ''
    Say (" Adapter counters over same window: received {0}, sent {1}" -f (Fmt-Bytes $r.AdRx), (Fmt-Bytes $r.AdTx))
    Say (" Sum attributed by ETW             : received {0}, sent {1}" -f (Fmt-Bytes $sRx), (Fmt-Bytes $sTx))
    $ur = [math]::Max(0, $r.AdRx - $sRx); $ut = [math]::Max(0, $r.AdTx - $sTx)
    Say (" UNATTRIBUTED (adapter minus ETW)  : received {0}, sent {1}" -f (Fmt-Bytes $ur), (Fmt-Bytes $ut)) Yellow
    Say ' The two sources will not match exactly: adapters count headers, ICMP, retransmits and non-TCP/UDP frames; ETW counts payload only.' DarkGray
    Say ' Router traffic, other devices, VPN/proxy tunnels and shared service hosts (svchost, System) also limit attribution.' DarkGray
    $up = @($r.Rows | Where-Object { $_.Upload -gt 5MB })
    foreach ($u in $up) { Say (" Notice: {0} (pid {1}) uploaded {2} in {3}s - verify this is expected (sync/backup/call/stream are common)." -f $u.Process, $u.PID, (Fmt-Bytes $u.Upload), $r.Seconds) Yellow }
    Write-EventRec 'BANDWIDTH_CAPTURE' ("{0}s top: {1}" -f $r.Seconds, ((@($r.Rows | Select-Object -First 3) | ForEach-Object { "{0}({1}) dn={2} up={3}" -f $_.Process, $_.PID, (Fmt-Bytes $_.Download), (Fmt-Bytes $_.Upload) }) -join '; '))
    Pause-Menu
}

# ------------------------------------------------- Module E: file activity
function Show-FileActivity {
    Head 'FILE ACTIVITY AND DOWNLOAD INVESTIGATION (read-only)'
    Say ' Windows does not record which process wrote which file unless Object Access auditing or a monitor like Sysmon is enabled.' DarkYellow
    Say ' This view lists recent files and shows TIMING coincidence with logged traffic bursts. Timing is NOT proof of a transfer.' DarkYellow
    Say ' Scope: Downloads, Desktop and Temp only. Document contents, browser passwords and tokens are never read.' DarkGray
    if ($Script:IsAdmin) {
        $ap = & auditpol /get /subcategory:"File System" 2>&1 | Out-String
        Say (" Audit policy (File System): {0}" -f (($ap -split "`r?`n" | Where-Object { $_ -match 'File System' } | Select-Object -First 1).Trim())) DarkGray
    }
    $mins = Ask-Int ' Look back how many minutes? [120]' 120
    $since = (Get-Date).AddMinutes(-$mins)
    $dirs = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", $env:TEMP) | Select-Object -Unique | Where-Object { Test-Path -LiteralPath $_ }
    $doHash = ((Read-Host ' Compute SHA-256 locally for files up to 100 MB? (y/N)').Trim().ToLower() -eq 'y')
    Say ' Scanning...' DarkGray
    $bursts = @()
    if (Test-Path $Script:EventsCsv) { $bursts = @(Import-Csv $Script:EventsCsv | Where-Object { $_.Type -eq 'BURST' } | ForEach-Object { [datetime]$_.Time }) }
    $rows = New-Object System.Collections.ArrayList
    foreach ($d in $dirs) {
        $fl = @(Get-ChildItem -LiteralPath $d -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $since -or $_.CreationTime -ge $since } | Select-Object -First 300)
        foreach ($f in $fl) {
            $flags = @()
            if ($f.Length -ge 500MB) { $flags += 'LARGE' }
            if ($f.Extension -match '(?i)^\.(exe|dll|scr|bat|cmd|ps1|vbs|js|msi|jar)$' -and ($f.FullName -like "$env:TEMP*" -or $f.FullName -like "*\Downloads\*")) { $flags += 'EXECUTABLE-TYPE' }
            if ($f.Name -match '(?i)\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|bat|cmd|js|vbs|ps1)$') { $flags += 'DOUBLE-EXTENSION' }
            if ($f.Attributes -band [IO.FileAttributes]::Hidden) { $flags += 'HIDDEN' }
            $zone = ''
            if ($f.FullName -like "*\Downloads\*") {
                $z = @(Get-Content -LiteralPath $f.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue)
                if ($z.Count -gt 0) { $zi = ($z | Where-Object { $_ -like 'ZoneId=*' } | Select-Object -First 1); $hu = ($z | Where-Object { $_ -like 'HostUrl=*' } | Select-Object -First 1); $dom = ''; if ($hu -match '^HostUrl=https?://([^/]+)') { $dom = $Matches[1] }; $zone = "$zi $dom" }
            }
            $hash = ''
            if ($doHash -and $f.Length -le 100MB) { try { $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.Substring(0, 16) + '...' } catch { $hash = '(locked)' } }
            $co = ''
            foreach ($b in $bursts) { if ([math]::Abs(($f.LastWriteTime - $b).TotalSeconds) -le 60) { $co = 'near burst ' + $b.ToString('HH:mm:ss'); break } }
            [void]$rows.Add([pscustomobject]@{ Modified = $f.LastWriteTime.ToString('MM-dd HH:mm:ss'); Created = $f.CreationTime.ToString('MM-dd HH:mm:ss'); Size = (Fmt-Bytes $f.Length); File = $f.FullName; Flags = ($flags -join ','); WebOrigin = $zone; SHA256 = $hash; Timing = $co })
        }
    }
    $sorted = @($rows | Sort-Object Modified -Descending)
    Say (" {0} files modified/created in the last {1} minutes (showing up to 40, newest first)" -f $sorted.Count, $mins)
    Show-Table ($sorted | Select-Object -First 40) @('Modified', 'Size', 'File', 'Flags', 'WebOrigin', 'Timing')
    if ($bursts.Count -eq 0) { Say ' No traffic bursts are logged (run the live monitor first for timing correlation).' DarkGray }
    $fl = @($sorted | Where-Object { $_.Flags })
    if ($fl.Count -gt 0) {
        Add-Finding -Module 'Files' -Title ("{0} recent file(s) with indicators" -f $fl.Count) -Evidence (($fl | Select-Object -First 3 | ForEach-Object { "$($_.File) [$($_.Flags)]" }) -join ' | ') -Severity 'Low' -Cause 'Large files, executables in download/temp folders and double extensions are common but worth a look' -Confidence 'Low' -Next 'Check the origin (WebOrigin), run a Defender scan on the file, compare hash with the publisher site manually' -Repair 'Quarantine (recoverable)' -Status 'Suspected'
        Show-Findings 'Files'
    }
    if ((Read-Host ' Export this list to CSV? (y/N)').Trim().ToLower() -eq 'y') {
        $f = Join-Path $Script:Dirs.Reports ("files_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        $sorted | Export-Csv $f -NoTypeInformation -Encoding UTF8; Say " Saved: $f (contains file paths and your user name)" Yellow
    }
    Pause-Menu
}

# ------------------------------------------------------ Module F: diagnostics
function Invoke-Diagnostics {
    Head 'NETWORK AND INTERNET DIAGNOSTICS (read-only, about 1 minute)'
    Say ' Running layered tests: local network first, then external...' DarkGray
    $s = Get-ConnState
    Say ''; Say ' 1. ADAPTERS' White
    Show-Table @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Not Present' } | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MediaConnectionState) @('Name', 'InterfaceDescription', 'Status', 'LinkSpeed')
    Say ''; Say ' 2. IP CONFIGURATION' White
    Say ("   Active adapter {0} [{1}]  IP {2}  Gateway {3}  DNS {4}" -f $s.Adapter, $s.Kind, $s.Ip, $s.Gateway, ($s.Dns -join ', '))
    if ($s.Ip -match '^169\.254\.') { Add-Finding -Module 'Network' -Title 'APIPA address (169.254.x.x)' -Evidence "IP $($s.Ip)" -Severity 'High' -Cause 'DHCP server did not answer' -Confidence 'High' -Next 'Check router/DHCP, cable or Wi-Fi association' -Repair 'Renew DHCP lease (not automated by NetWatch)' -Status 'Confirmed' }
    Say ''; Say ' 3. LOCAL NETWORK: gateway latency (10 pings)' White
    $g = $null
    if ($s.Gateway) { $g = Get-PingStats $s.Gateway 10; Say ("   {0}: loss {1}%  avg {2} ms  max {3} ms  jitter {4} ms" -f $g.Host, $g.LossPct, $g.AvgMs, $g.MaxMs, $g.JitterMs) } else { Say '   no default gateway' Yellow }
    Say ''; Say ' 4. EXTERNAL REACHABILITY (10 pings to 1.1.1.1)' White
    $e = Get-PingStats '1.1.1.1' 10; Say ("   {0}: loss {1}%  avg {2} ms  max {3} ms  jitter {4} ms" -f $e.Host, $e.LossPct, $e.AvgMs, $e.MaxMs, $e.JitterMs)
    Say ("   TCP 1.1.1.1:443 {0};  TCP www.msftconnecttest.com:80 {1}" -f $(if ($s.ExtTcp) { 'OK' } else { 'FAILED' }), $(if ($s.WebTcp) { 'OK' } else { 'FAILED' }))
    Say ''; Say ' 5. DNS (each configured server queried directly, 3 lookups each)' White
    $dnsAvg = @{}
    foreach ($d in (@($s.Dns) + '1.1.1.1')) {
        $t = @(); $ok = 0
        foreach ($nm in 'www.microsoft.com', 'www.wikipedia.org', 'www.example.com') { $m = Measure-Dns $nm $d; if ($m.Ok) { $ok++; $t += $m.Ms } }
        $av = 0; if ($t.Count) { $av = [math]::Round(($t | Measure-Object -Average).Average, 0) }
        $dnsAvg[$d] = $av
        $tag = ''; if ($d -eq '1.1.1.1') { $tag = ' (public reference)' }
        Say ("   {0,-18} {1}/3 answered, avg {2} ms{3}" -f $d, $ok, $av, $tag)
        if ($ok -eq 0 -and $d -ne '1.1.1.1') { Add-Finding -Module 'Network' -Title "DNS server $d not answering" -Evidence '0 of 3 test lookups answered' -Severity 'High' -Cause 'DNS server down, blocked, or wrong DNS setting' -Confidence 'Medium' -Next 'Try a different DNS server in adapter settings; compare with router DNS' -Repair 'Flush DNS cache (Repair Center) only helps if the cache is stale' -Status 'Confirmed' }
    }
    Say ''; Say ' 6. PROXY / VPN' White
    $ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($ie -and $ie.ProxyEnable -eq 1) { Say ("   User proxy ENABLED: {0}" -f $ie.ProxyServer) Yellow } else { Say '   User proxy: off' }
    if ($ie -and $ie.AutoConfigURL) { Say ("   Auto-config script: {0}" -f $ie.AutoConfigURL) Yellow }
    $wh = (& netsh winhttp show proxy 2>&1 | Out-String).Trim() -replace '\s+', ' '
    Say ("   WinHTTP: {0}" -f $wh)
    $vpn = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -match '(?i)vpn|tap-|wireguard|tunnel|anyconnect|fortinet|pulse|openvpn' })
    if ($vpn.Count) { Say ("   VPN/tunnel adapter up: {0}. Traffic attribution and speed may differ." -f (($vpn | ForEach-Object Name) -join ', ')) Yellow } else { Say '   No VPN/tunnel adapter detected' }
    Say ''; Say ' 7. WI-FI (best effort; labels are English)' White
    $wl = (& netsh wlan show interfaces 2>&1 | Out-String)
    $wif = @($wl -split "`r?`n" | Where-Object { $_ -match '^\s*(State|Radio type|Channel|Receive rate|Transmit rate|Signal)\s*:' })
    if ($wif.Count) { $wif | ForEach-Object { Say ("   " + $_.Trim()) }
        $sg = $wl -split "`r?`n" | Where-Object { $_ -match '^\s*Signal\s*:\s*(\d+)%' } | ForEach-Object { [int]$Matches[1] } | Select-Object -First 1
        if ($sg -and $sg -lt 50) { Add-Finding -Module 'Network' -Title "Weak Wi-Fi signal ($sg%)" -Evidence "Signal $sg%" -Severity 'Medium' -Cause 'Distance, walls or interference' -Confidence 'Medium' -Next 'Move closer to the access point or use 5 GHz/Ethernet; re-run the gateway test' -Status 'Confirmed' }
    } else { Say '   No Wi-Fi interface information (wired connection or unsupported)' DarkGray }
    Say ''; Say ' 8. BANDWIDTH SATURATION (5s adapter sample)' White
    $a0 = Get-AdapterTotals; Start-Sleep -Seconds 5; $a1 = Get-AdapterTotals
    $dn = ($a1.Rx - $a0.Rx) / 5; $up = ($a1.Tx - $a0.Tx) / 5
    $ls = 0; $ph = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }); if ($ph.Count) { try { $ls = [double]$ph[0].ReceiveLinkSpeed } catch {} }
    Say ("   Download {0}, upload {1} (adapter counters, measured)" -f (Fmt-Rate $dn), (Fmt-Rate $up))
    $sat = $false
    if ($ls -gt 0) { $uu = [math]::Max($dn, $up) * 8 / $ls * 100; Say ("   {0:N1}% of the adapter link speed (link speed is not your ISP speed)" -f $uu); if ($uu -gt 80) { $sat = $true } }
    # interpretation
    Say ''; Say ' INTERPRETATION' Cyan
    $gwBad = ($g -and $g.LossPct -ge 10); $extBad = ($e.LossPct -ge 10)
    if ($s.Level -eq 'ONLINE' -and -not $gwBad -and -not $extBad) { Say '   All layers work with low loss. If the web feels slow, suspect the remote site, DNS speed, Wi-Fi quality, or legitimate downloads (see menu 4).' Green }
    if ($gwBad) { Say ("   Gateway loss {0}%: the problem is on your LOCAL network (Wi-Fi signal/interference, cable, router load). The ISP is not the cause." -f $g.LossPct) Yellow; Add-Finding -Module 'Network' -Title 'Packet loss to gateway' -Evidence ("{0}% loss to {1}" -f $g.LossPct, $g.Host) -Severity 'High' -Cause 'Wi-Fi interference/weak signal, faulty cable or router overload' -Confidence 'Medium' -Next 'Test on Ethernet, move closer, restart router (manual)' -Status 'Confirmed' }
    elseif ($extBad -and $g) { Say ("   Gateway is fine but external loss is {0}%: likely router uplink, modem or ISP." -f $e.LossPct) Yellow; Add-Finding -Module 'Network' -Title 'Packet loss to external host' -Evidence ("{0}% loss to 1.1.1.1; gateway {1}% loss" -f $e.LossPct, $g.LossPct) -Severity 'Medium' -Cause 'ISP/modem/uplink problem' -Confidence 'Medium' -Next 'Test from another device; contact ISP with these numbers' -Status 'Confirmed' }
    if ($e.AvgMs -gt 150) { Say ("   High external latency ({0} ms): can be distance, congestion, VPN, or saturation." -f $e.AvgMs) Yellow; Add-Finding -Module 'Network' -Title 'High latency' -Evidence ("avg {0} ms to 1.1.1.1" -f $e.AvgMs) -Severity 'Medium' -Cause 'Congestion, VPN, Wi-Fi quality or an active large transfer' -Confidence 'Low' -Next 'Repeat with VPN off and downloads paused' -Status 'Confirmed' }
    if ($s.Level -eq 'DNS-FAIL') { Say '   External IPs work but DNS fails: change/verify DNS servers; flush DNS cache is a low-risk first step.' Yellow; Add-Finding -Module 'Network' -Title 'DNS resolution failing while IP connectivity works' -Evidence ("level {0}; dns {1}" -f $s.Level, ($s.Dns -join ',')) -Severity 'High' -Cause 'DNS server problem or stale/negative cache' -Confidence 'High' -Next 'Test other DNS server; then flush cache' -Repair 'Flush DNS cache' -Status 'Confirmed' -Outcome 'SAFE CANDIDATE' }
    $refs = @($dnsAvg.GetEnumerator() | Where-Object { $_.Key -ne '1.1.1.1' -and $_.Value -gt 0 })
    foreach ($r in $refs) { if ($dnsAvg['1.1.1.1'] -gt 0 -and $r.Value -gt 3 * $dnsAvg['1.1.1.1'] -and $r.Value -gt 150) { Say ("   DNS server {0} answers slowly ({1} ms vs {2} ms public reference): consider another DNS provider." -f $r.Key, $r.Value, $dnsAvg['1.1.1.1']) Yellow; Add-Finding -Module 'Network' -Title "Slow DNS server $($r.Key)" -Evidence ("{0} ms vs {1} ms reference" -f $r.Value, $dnsAvg['1.1.1.1']) -Severity 'Low' -Cause 'ISP/router DNS slow' -Confidence 'Medium' -Next 'Try another DNS provider manually' -Status 'Confirmed' } }
    if ($sat) { Say '   The link is nearly saturated: something is transferring heavily. Use menu 4 to see which process.' Yellow }
    if ($ie -and $ie.ProxyEnable -eq 1 -and -not $s.WebTcp) { Say '   A proxy is enabled and web TCP failed: a wrong proxy is a common cause.' Yellow }
    if ($s.Level -ne 'ONLINE') { Say ("   Level: {0} - {1}" -f $s.Level, (Get-LevelText $s.Level)) Yellow }
    Say '   NetWatch never applies disruptive network resets automatically.' DarkGray
    Write-EventRec 'DIAGNOSTICS' ("level={0} gwLoss={1} extLoss={2} extAvg={3}ms" -f $s.Level, $(if ($g) { $g.LossPct } else { 'n/a' }), $e.LossPct, $e.AvgMs)
    Show-Findings 'Network'
    Pause-Menu
}

# ------------------------------------------------------- Module H: security
function Invoke-SecurityScan {
    Head 'SECURITY AND SUSPICIOUS ACTIVITY SCAN (read-only)'
    Say ' Results are INDICATORS, not confirmed threats. Nothing is uploaded, quarantined or terminated by this scan.' DarkYellow
    $m = 'Security'
    Say ' Checking Windows security status...' DarkGray
    $mp = $null; try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch {}
    if ($mp) {
        Say (" Defender: antivirus {0}, real-time protection {1}, signatures age {2} day(s), last quick scan {3}" -f $mp.AMServiceEnabled, $mp.RealTimeProtectionEnabled, $mp.AntivirusSignatureAge, $mp.QuickScanEndTime)
        if (-not $mp.RealTimeProtectionEnabled) { Add-Finding -Module $m -Title 'Defender real-time protection is off' -Evidence 'RealTimeProtectionEnabled=False' -Severity 'Medium' -Cause 'Disabled by the user, policy or another AV product' -Confidence 'Medium' -Next 'Confirm another AV product is active (Windows Security > Virus protection)' -Status 'Confirmed' -Outcome 'PROTECTED' }
        if ($mp.AntivirusSignatureAge -gt 7) { Add-Finding -Module $m -Title 'Defender signatures are old' -Evidence ("{0} days old" -f $mp.AntivirusSignatureAge) -Severity 'Low' -Cause 'Updates blocked or offline' -Confidence 'High' -Next 'Run Windows Update / Update-MpSignature manually' -Status 'Confirmed' }
    } else { Say ' Defender status unavailable (another AV may be active, or insufficient rights).' DarkGray }
    $av = @(); try { $av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object { $_.displayName }) } catch {}
    if ($av.Count) { Say (" Registered AV products: {0}" -f ($av -join ', ')) }
    $th = @(); try { $th = @(Get-MpThreatDetection -ErrorAction Stop) } catch {}
    if ($th.Count -gt 0) {
        Say (" Defender recorded {0} detection(s):" -f $th.Count) Yellow
        $th | Select-Object -First 5 | ForEach-Object { Say ("   {0}  threatId {1}  {2}" -f $_.InitialDetectionTime, $_.ThreatID, ($_.Resources | Select-Object -First 1)) DarkGray }
        Add-Finding -Module $m -Title "Defender detection history ($($th.Count))" -Evidence 'Get-MpThreatDetection returned entries' -Severity 'High' -Cause 'Defender flagged files; remediation status not verified here' -Confidence 'High' -Next 'Open Windows Security > Protection history and review each item' -Repair 'Defender scan / quarantine via Windows Security' -Status 'Confirmed (reported by Defender)'
    } else { Say ' No Defender threat detections in history.' Green }
    Say ''; Say ' Reviewing external connections by process...' DarkGray
    $pt = Get-ProcTable
    $est = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1)' })
    $byProc = $est | Group-Object OwningProcess
    $sus = @()
    foreach ($g in $byProc) {
        $p = $pt[[int]$g.Name]; if (-not $p) { continue }
        $cls = Get-Classification -Path $p.ExecutablePath -Kind 'Process' -Name $p.Name
        if ($cls.Outcome -eq 'PROTECTED') { continue }
        $sg = Get-Sig $p.ExecutablePath; $flags = @()
        if ($p.ExecutablePath -and $sg.Status -ne 'Valid') { $flags += "signature $($sg.Status)" }
        if ($p.ExecutablePath -and (Test-UserWritablePath $p.ExecutablePath) -and ($p.ExecutablePath -match '(?i)\\(Temp|Downloads|Public)\\')) { $flags += 'runs from Temp/Downloads/Public' }
        if (-not $p.ExecutablePath) { $flags += 'path inaccessible' }
        if ($flags.Count -gt 0) { $sus += [pscustomobject]@{ Process = $p.Name; PID = $g.Name; Conns = $g.Count; Flags = ($flags -join '; '); Remote = (($g.Group | Select-Object -First 2 | ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort)" }) -join ', '); Outcome = $cls.Outcome } }
    }
    if ($sus.Count) {
        Say (" {0} process(es) with external connections have indicators (frequently legitimate - verify, do not assume):" -f $sus.Count) Yellow
        Show-Table $sus @('Process', 'PID', 'Conns', 'Flags', 'Remote', 'Outcome')
        foreach ($x in $sus) { Add-Finding -Module $m -Title ("Outbound connection from {0} (pid {1})" -f $x.Process, $x.PID) -Evidence $x.Flags -Severity 'Medium' -Cause 'Unsigned or portable software, installers, games and developer tools commonly look like this' -Confidence 'Low' -Next 'Check the path and publisher; scan the file with Defender; observe over time' -Repair 'Defender scan; quarantine only after review' -Status 'Suspected' }
    } else { Say ' No external connections from unsigned / Temp-located / unidentifiable processes.' Green }
    Say ''; Say ' Listening ports reachable from the network...' DarkGray
    $lis = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -notmatch '^(127\.|::1)' })
    $lrows = foreach ($l in $lis) {
        $p = $pt[[int]$l.OwningProcess]; $pth = $null; $nm = "pid $($l.OwningProcess)"; if ($p) { $pth = $p.ExecutablePath; $nm = $p.Name }
        $inWin = ($pth -and $pth.StartsWith($env:windir, [StringComparison]::OrdinalIgnoreCase))
        if (-not $inWin) { [pscustomobject]@{ Process = $nm; PID = $l.OwningProcess; Port = $l.LocalPort; Bind = $l.LocalAddress; Signature = (Get-Sig $pth).Status; Path = $pth } }
    }
    $lrows = @($lrows | Sort-Object Port)
    if ($lrows.Count) { Say (" {0} non-Windows listener(s) bound beyond loopback:" -f $lrows.Count); Show-Table ($lrows | Select-Object -First 25) @('Process', 'PID', 'Port', 'Bind', 'Signature', 'Path')
        $bad = @($lrows | Where-Object { $_.Signature -ne 'Valid' })
        if ($bad.Count) { Add-Finding -Module $m -Title ("{0} unsigned/unverifiable listening service(s)" -f $bad.Count) -Evidence (($bad | Select-Object -First 3 | ForEach-Object { "$($_.Process):$($_.Port)" }) -join ', ') -Severity 'Low' -Cause 'Dev servers, game servers and portable tools often listen' -Confidence 'Low' -Next 'Confirm each is expected; check firewall rules' -Status 'Suspected' }
    } else { Say ' No non-Windows listeners beyond loopback.' Green }
    Say ''; Say ' Startup items and scheduled tasks...' DarkGray
    $ents = Get-StartupEntries
    $con = @($ents | Where-Object { $_.Concerns -match 'obfuscated|user-writable' })
    foreach ($c in ($con | Select-Object -First 8)) {
        Say ("   {0}: {1} -> {2}" -f $c.Source, $c.Name, $c.Concerns) Yellow
        Add-Finding -Module $m -Title ("Startup item: {0}" -f $c.Name) -Evidence ("{0}; {1}" -f $c.Source, $c.Concerns) -Severity 'Medium' -Cause 'Persistence mechanisms are used by both legitimate apps and malware' -Confidence 'Low' -Next 'Verify the publisher and install date' -Repair 'Disable (reversible) after review' -Status 'Suspected' -Outcome $c.Outcome
    }
    if (-not $con.Count) { Say ' No startup entries with the checked indicators.' Green }
    Say ''; Say ' Configuration checks (hosts file, new services)...' DarkGray
    $hosts = @(Get-Content "$env:windir\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*[0-9a-fA-F:\.]+\s+\S+' -and $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*(127\.0\.0\.1|::1)\s+localhost\s*$' })
    if ($hosts.Count) { Say (" hosts file has {0} custom entr(ies); review them." -f $hosts.Count) Yellow; Add-Finding -Module $m -Title 'Custom hosts file entries' -Evidence ("{0} entries" -f $hosts.Count) -Severity 'Low' -Cause 'Ad-blocking, dev setups; sometimes redirects by malware' -Confidence 'Low' -Next 'Open C:\Windows\System32\drivers\etc\hosts in Notepad (admin) and review' -Status 'Suspected' } else { Say ' hosts file: no custom entries.' Green }
    $ns = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = (Get-Date).AddDays(-14) } -ErrorAction SilentlyContinue | Select-Object -First 10)
    if ($ns.Count) { Say (" {0} service installation(s) in the last 14 days:" -f $ns.Count); $ns | ForEach-Object { Say ("   {0}  {1}  {2}" -f $_.TimeCreated.ToString('MM-dd HH:mm'), $_.Properties[0].Value, $_.Properties[1].Value) DarkGray } } else { Say ' No new services installed in the last 14 days.' }
    if ($Script:IsAdmin) {
        $fl = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddHours(-24) } -ErrorAction SilentlyContinue)
        Say (" Failed logons (event 4625) in last 24h: {0}" -f $fl.Count); if ($fl.Count -ge 20) { Add-Finding -Module $m -Title 'Many failed logons' -Evidence ("{0} in 24h" -f $fl.Count) -Severity 'Medium' -Cause 'Mistyped passwords, services with stale credentials, or remote guessing' -Confidence 'Low' -Next 'Review Event Viewer > Security > 4625 source addresses' -Status 'Confirmed' }
    } else { Say ' Failed-logon check needs Administrator (Security log).' DarkGray }
    $bu = @(); if (Test-Path $Script:EventsCsv) { $bu = @(Import-Csv $Script:EventsCsv | Where-Object { $_.Type -eq 'BURST' -and $_.Detail -match 'UPLOAD' }) }
    Say (" Logged upload-dominant bursts (all sessions): {0}" -f $bu.Count)
    if ($bu.Count -ge 3) { Add-Finding -Module $m -Title 'Repeated upload-dominant bursts' -Evidence ("{0} logged" -f $bu.Count) -Severity 'Low' -Cause 'Backups, cloud sync, video calls, uploads' -Confidence 'Low' -Next 'Run menu 4 during an upload burst to see the process' -Status 'Suspected' }
    Show-Findings $m
    Say ''; Say ' Optional: Windows Defender quick scan is available in the Repair Center (option 8).' DarkGray
    Pause-Menu
}

# ----------------------------------------------------- Module G: system health
function Invoke-HealthCheck {
    Head 'WINDOWS BUG AND SYSTEM HEALTH CHECK (read-only)'
    $m = 'Health'
    Say ' Reading event logs (last 7 days)...' DarkGray
    $since = (Get-Date).AddDays(-7)
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System', 'Application'; Level = 1, 2; StartTime = $since } -MaxEvents 3000 -ErrorAction SilentlyContinue)
    Say (" {0} critical/error events found." -f $ev.Count)
    $top = @($ev | Group-Object { "{0}|{1}" -f $_.ProviderName, $_.Id } | Sort-Object Count -Descending | Select-Object -First 6)
    foreach ($t in $top) { $f = $t.Group[0]; $msg = ($f.Message -split "`r?`n")[0]; if ($msg.Length -gt 100) { $msg = $msg.Substring(0, 100) + '...' }; Say ("   {0,4}x  {1} (id {2})  {3}" -f $t.Count, $f.ProviderName, $f.Id, $msg) DarkGray }
    $crash = @($ev | Where-Object { $_.ProviderName -eq 'Application Error' -and $_.Id -eq 1000 } | Group-Object { [string]$_.Properties[0].Value } | Where-Object { $_.Count -ge 3 })
    foreach ($c in $crash) { Add-Finding -Module $m -Title ("Application crashing repeatedly: {0}" -f $c.Name) -Evidence ("{0} crash events in 7 days, latest {1}" -f $c.Count, $c.Group[0].TimeCreated) -Severity 'Medium' -Cause 'Faulty update, corrupt install, incompatible plug-in/driver' -Confidence 'Medium' -Next 'Update or repair the application; check Reliability Monitor' -Repair 'None automated' -Status 'Confirmed error' }
    $svc = @($ev | Where-Object { $_.ProviderName -eq 'Service Control Manager' -and $_.Id -in 7000, 7001, 7009, 7011, 7031, 7034 } | Group-Object { [string]$_.Properties[0].Value } | Where-Object { $_.Count -ge 2 })
    foreach ($c in $svc) { Add-Finding -Module $m -Title ("Service failures: {0}" -f $c.Name) -Evidence ("{0} events, latest {1}" -f $c.Count, $c.Group[0].TimeCreated) -Severity 'Medium' -Cause 'Service crash, dependency failure or timeout' -Confidence 'Medium' -Next 'Check service dependencies and the application log around the time' -Repair 'Review service (manual); not changed automatically' -Status 'Confirmed error' }
    $net = @($ev | Where-Object { $_.ProviderName -match '(?i)Tcpip|Dhcp|DNS|NDIS|WLAN|NetBT|Netwtw|e1|rt640|Netwbw' })
    if ($net.Count -ge 3) { Add-Finding -Module $m -Title 'Network-related error events' -Evidence ("{0} events from {1}" -f $net.Count, (($net | Group-Object ProviderName | Select-Object -First 3 -ExpandProperty Name) -join ', ')) -Severity 'Low' -Cause 'Driver issues, DHCP/DNS outages, adapter resets' -Confidence 'Low' -Next 'Update the network driver; correlate times with outages in the monitor log' -Status 'Suspected' }
    Say ''; Say ' Sampling CPU, memory, disk (about 8 seconds)...' DarkGray
    $cpuS = @(); $dskS = @(); $qS = @()
    for ($i = 0; $i -lt 4; $i++) {
        $c = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction SilentlyContinue; if ($c) { $cpuS += [double]$c.PercentProcessorTime }
        $d = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'" -ErrorAction SilentlyContinue; if ($d) { $dskS += [double]$d.PercentDiskTime; $qS += [double]$d.CurrentDiskQueueLength }
        Start-Sleep -Seconds 2
    }
    $cpu = 0; if ($cpuS.Count) { $cpu = [math]::Round(($cpuS | Measure-Object -Average).Average, 0) }
    $dsk = 0; if ($dskS.Count) { $dsk = [math]::Round(($dskS | Measure-Object -Average).Average, 0) }
    $q = 0; if ($qS.Count) { $q = [math]::Round(($qS | Measure-Object -Average).Average, 1) }
    $os = Get-CimInstance Win32_OperatingSystem
    $memPct = [math]::Round(100 * (1 - $os.FreePhysicalMemory / $os.TotalVisibleMemorySize), 0)
    Say (" CPU {0}%   Memory used {1}%   Disk busy {2}% (queue {3})   Uptime {4:N1} days" -f $cpu, $memPct, $dsk, $q, ((Get-Date) - $os.LastBootUpTime).TotalDays)
    $cores = [int]$env:NUMBER_OF_PROCESSORS; if ($cores -lt 1) { $cores = 1 }
    $pp = @(Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin '_Total', 'Idle' })
    $tc = @($pp | Sort-Object PercentProcessorTime -Descending | Select-Object -First 5 | ForEach-Object { [pscustomobject]@{ Process = $_.Name; PID = $_.IDProcess; 'CPU %' = [math]::Round($_.PercentProcessorTime / $cores, 1); 'Memory' = (Fmt-Bytes $_.WorkingSet) } })
    Say ' Top CPU (instantaneous):' DarkGray; Show-Table $tc @('Process', 'PID', 'CPU %', 'Memory')
    $ti = @($pp | Sort-Object { $_.IOReadBytesPersec + $_.IOWriteBytesPersec } -Descending | Select-Object -First 5 | ForEach-Object { [pscustomobject]@{ Process = $_.Name; PID = $_.IDProcess; 'IO/s (disk+network+other)' = (Fmt-Rate ($_.IOReadBytesPersec + $_.IOWriteBytesPersec)) } })
    Say ' Top I/O (includes disk AND network I/O - not a network measurement):' DarkGray; Show-Table $ti @('Process', 'PID', 'IO/s (disk+network+other)')
    if ($cpu -ge 90) { Add-Finding -Module $m -Title 'Sustained high CPU' -Evidence ("avg {0}% over 8s; top: {1}" -f $cpu, ($tc[0].Process)) -Severity 'Medium' -Cause 'Busy application, scan, update or runaway process' -Confidence 'Medium' -Next 'Identify the top process; wait for updates/scans to finish' -Repair 'Stop a verified runaway process (Repair Center)' -Status 'Confirmed' }
    if ($memPct -ge 90) { Add-Finding -Module $m -Title 'High memory usage' -Evidence ("{0}% used" -f $memPct) -Severity 'Medium' -Cause 'Too many apps/browser tabs or a leak' -Confidence 'Medium' -Next 'Close heavy apps; review top memory processes' -Status 'Confirmed' }
    if ($dsk -ge 90 -or $q -ge 3) { Add-Finding -Module $m -Title 'Excessive disk activity' -Evidence ("busy {0}% queue {1}" -f $dsk, $q) -Severity 'Medium' -Cause 'Indexing, update, antivirus scan, failing disk or low RAM' -Confidence 'Low' -Next 'Check top I/O processes; check disk health (SMART) and free RAM' -Status 'Confirmed' }
    foreach ($ld in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue)) { if ($ld.Size -gt 0 -and ($ld.FreeSpace / $ld.Size) -lt 0.1) { Add-Finding -Module $m -Title ("Low free space on {0}" -f $ld.DeviceID) -Evidence ("{0} free of {1}" -f (Fmt-Bytes $ld.FreeSpace), (Fmt-Bytes $ld.Size)) -Severity 'Medium' -Cause 'Disk nearly full hurts updates and performance' -Confidence 'High' -Next 'Free space (Storage settings); review temp files in the Repair Center' -Repair 'Quarantine old temp files' -Status 'Confirmed' } }
    foreach ($a in @(Get-NetAdapterStatistics -ErrorAction SilentlyContinue)) { $er = [double]$a.ReceivedPacketErrors + [double]$a.OutboundPacketErrors; $tt = [double]$a.ReceivedUnicastPackets + [double]$a.SentUnicastPackets; if ($er -gt 100 -and $tt -gt 0 -and ($er / $tt) -gt 0.001) { Add-Finding -Module $m -Title ("Adapter errors on {0}" -f $a.Name) -Evidence ("{0} packet errors of {1} packets since boot/driver load" -f $er, $tt) -Severity 'Low' -Cause 'Cable, driver or interference' -Confidence 'Low' -Next 'Reseat/replace cable; update driver' -Status 'Suspected' } }
    $rb = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $rb += 'Component servicing' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $rb += 'Windows Update' }
    if ($rb.Count) { Add-Finding -Module $m -Title 'Restart pending' -Evidence ($rb -join ', ') -Severity 'Low' -Cause 'Updates waiting for a restart' -Confidence 'High' -Next 'Restart when convenient' -Status 'Optimization opportunity' }
    $ents = Get-StartupEntries
    $brk = @($ents | Where-Object { $_.Concerns -match 'broken entry' })
    foreach ($b in $brk) { Add-Finding -Module $m -Title ("Broken startup entry: {0}" -f $b.Name) -Evidence ("{0}: target {1} missing" -f $b.Source, $b.Path) -Severity 'Low' -Cause 'Program removed without cleaning its startup entry' -Confidence 'High' -Next 'Confirm the program is uninstalled' -Repair 'Disable the entry (reversible) in the Repair Center' -Status 'Confirmed error' -Outcome $b.Outcome }
    Say ''
    if ($Script:IsAdmin) {
        if ((Read-Host ' Run read-only System File Checker verification now (sfc /verifyonly, 5-15 min)? (y/N)').Trim().ToLower() -eq 'y') {
            Say ' Running sfc /verifyonly (changes nothing)...' DarkGray
            $o = ((& sfc /verifyonly 2>&1) -join ' ') -replace "`0", ''
            if ($o -match 'did not find any integrity violations') { Say ' SFC: no integrity violations.' Green }
            elseif ($o -match 'found integrity violations') { Add-Finding -Module $m -Title 'System file integrity violations' -Evidence 'sfc /verifyonly reported violations' -Severity 'High' -Cause 'Corrupt or modified system files' -Confidence 'High' -Next 'Run DISM /ScanHealth, then repair in the Repair Center (option 9)' -Repair 'DISM RestoreHealth + SFC /scannow (needs approval)' -Status 'Confirmed error' -Outcome 'NEEDS REVIEW' }
            else { Say (" SFC result could not be classified: {0}" -f $o.Substring(0, [math]::Min(200, $o.Length))) Yellow }
        }
    } else { Say ' SFC/DISM checks need Administrator (use settings to relaunch elevated).' DarkGray }
    Write-EventRec 'HEALTH_CHECK' ("cpu={0}% mem={1}% disk={2}% findings={3}" -f $cpu, $memPct, $dsk, @($Script:Findings | Where-Object { $_.Module -eq $m }).Count)
    Show-Findings $m
    Pause-Menu
}

# ------------------------------------------------------ Module J: repair center
function Invoke-Repair {
    param([hashtable]$Plan, [scriptblock]$Backup, [scriptblock]$Do, [scriptblock]$Verify)
    Head ("REPAIR PLAN: " + $Plan.Title)
    Say (" 1. Issue            : {0}" -f $Plan.Issue)
    Say (" 2. Evidence         : {0}" -f $Plan.Evidence)
    Say (" 3. Proposed action  : {0}" -f $Plan.Action)
    Say (" 4. Exact target     : {0}" -f $Plan.Target) White
    Say (" 5. Expected effect  : {0}" -f $Plan.Effect)
    Say (" 6. Classification   : {0}" -f $Plan.Outcome) (Out-Color $Plan.Outcome)
    Say (" 7. Admin required   : {0} (currently elevated: {1})" -f $Plan.Admin, $Script:IsAdmin)
    Say (" 8. Backup/recovery  : {0}" -f $Plan.Recovery)
    if ($Plan.Outcome -eq 'PROTECTED') { Say "`n REFUSED: this item is PROTECTED. Routine repair/cleanup is not offered." Magenta; Write-EventRec 'REPAIR_REFUSED' ("{0} | PROTECTED" -f $Plan.Title); Pause-Menu; return $false }
    if ($Plan.Admin -and -not $Script:IsAdmin) { Say "`n This action requires Administrator rights. Use Settings > Relaunch as Administrator." Yellow; Pause-Menu; return $false }
    Say ''
    if (-not (Confirm-Action ' Approve THIS single action?')) { Say ' Cancelled. Nothing was changed.' Green; Write-EventRec 'REPAIR_DECLINED' $Plan.Title; Pause-Menu; return $false }
    if ($Backup) {
        $bk = $null; try { $bk = & $Backup } catch { $bk = [pscustomobject]@{ Ok = $false; Info = $_.Exception.Message } }
        if (-not $bk.Ok) { Say (" Backup/recovery step FAILED ({0}). Aborting; nothing was changed." -f $bk.Info) Red; Write-EventRec 'REPAIR_ABORTED' ("{0} | backup failed: {1}" -f $Plan.Title, $bk.Info); Pause-Menu; return $false }
        Say (" Recovery verified: {0}" -f $bk.Info) Green
    }
    $err = $null
    try { & $Do | Out-Null } catch { $err = $_.Exception.Message }
    if ($err) { Say (" Action error: {0}" -f $err) Red }
    $v = $null; try { $v = & $Verify } catch { $v = [pscustomobject]@{ Ok = $false; Info = $_.Exception.Message } }
    if ($v.Ok) { Say (" VERIFIED: {0}" -f $v.Info) Green } else { Say (" NOT VERIFIED: {0}" -f $v.Info) Red }
    Write-EventRec 'REPAIR' ("{0} | target={1} | verified={2} | {3} | error={4}" -f $Plan.Title, $Plan.Target, $v.Ok, $v.Info, $err)
    Pause-Menu
    return [bool]$v.Ok
}
function Move-ToQuarantine($file, $reason) {
    $item = Get-Item -LiteralPath $file -Force -ErrorAction Stop
    $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256 -ErrorAction Stop).Hash
    $id = (Get-Date -Format 'yyyyMMdd_HHmmss') + '_' + [guid]::NewGuid().ToString('N').Substring(0, 6)
    $dest = Join-Path $Script:Dirs.Quarantine ($id + '.qfile')
    Move-Item -LiteralPath $file -Destination $dest -Force -ErrorAction Stop
    $man = [pscustomobject]@{ Id = $id; OriginalPath = $file; Sha256 = $hash; Size = $item.Length; QuarantinedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); Reason = $reason; StoredAs = $dest; Restore = "NetWatch > 9 > 7, or move '$dest' back to '$file'" }
    $man | ConvertTo-Json | Set-Content -Path ($dest + '.json') -Encoding UTF8
    $ok = (Test-Path -LiteralPath $dest) -and -not (Test-Path -LiteralPath $file) -and ((Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash -eq $hash)
    return [pscustomobject]@{ Ok = $ok; Id = $id }
}
function Pick-StartupEntry {
    $ents = @(Get-StartupEntries | Where-Object { $_.Kind -eq 'Registry' -and $_.Source -notmatch 'RunOnce' -and $_.State -notmatch 'Disabled' })
    if (-not $ents.Count) { Say ' No Run-key entries available.' Yellow; return $null }
    $i = 0; $t = foreach ($e in $ents) { $i++; [pscustomobject]@{ '#' = $i; Source = $e.Source; Name = $e.Name; Signature = $e.Signature; Outcome = $e.Outcome; Concerns = $e.Concerns } }
    Show-Table $t @('#', 'Source', 'Name', 'Signature', 'Outcome', 'Concerns')
    $n = Ask-Int ' Entry number (0 = cancel)' 0
    if ($n -lt 1 -or $n -gt $ents.Count) { return $null }
    return $ents[$n - 1]
}
function Repair-DisableStartup {
    $e = Pick-StartupEntry; if (-not $e) { return }
    $prop = Get-ItemProperty -Path $e.RegPath -Name $e.Name -ErrorAction SilentlyContinue
    $kind = 'String'; try { $kind = (Get-Item $e.RegPath).GetValueKind($e.Name).ToString() } catch {}
    $isLm = $e.RegPath -like 'HKLM:*'
    $plan = @{ Title = 'Disable startup entry (Run key)'; Issue = ("Startup entry '{0}' ({1})" -f $e.Name, $e.Source); Evidence = ''; Action = 'Remove the value from the Run key after saving it for restoration (the program itself is not touched)'; Target = ("{0}  value '{1}' = {2}" -f $e.RegPath, $e.Name, $e.Command); Effect = 'The program will no longer start automatically at logon. Side effects: its tray icon/sync/updater will not run until you start it.'; Outcome = $e.Outcome; Admin = $isLm; Recovery = 'Registry key exported with reg.exe AND value saved in NetWatch data; restore via option 7' }
    $plan.Evidence = ("signature {0}; concerns: {1}; classification evidence: {2}" -f $e.Signature, $(if ($e.Concerns) { $e.Concerns } else { 'none' }), ($e.Cls.Evidence -join ' / '))
    $bk = {
        $f = Join-Path $Script:Dirs.Backups ("run_{0}.reg" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        & reg.exe export ($e.RegPath -replace ':', '') $f /y 2>&1 | Out-Null
        $rec = @(); if (Test-Path $Script:DisabledFile) { try { $rec = @(Get-Content $Script:DisabledFile -Raw | ConvertFrom-Json) } catch {} }
        $rec += [pscustomobject]@{ Time = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); RegPath = $e.RegPath; Name = $e.Name; Value = [string]$prop.($e.Name); Kind = $kind }
        ConvertTo-Json -InputObject @($rec) | Set-Content $Script:DisabledFile -Encoding UTF8
        $ok = (Test-Path $f) -and ((Get-Item $f).Length -gt 0) -and ((Get-Content $Script:DisabledFile -Raw) -match [regex]::Escape($e.Name))
        [pscustomobject]@{ Ok = $ok; Info = "$f and $Script:DisabledFile" }
    }
    $do = { Remove-ItemProperty -Path $e.RegPath -Name $e.Name -ErrorAction Stop }
    $vf = { $still = Get-ItemProperty -Path $e.RegPath -Name $e.Name -ErrorAction SilentlyContinue; $gone = (-not $still); [pscustomobject]@{ Ok = $gone; Info = $(if ($gone) { 'entry no longer present in the Run key' } else { 'entry still present' }) } }
    $script:StartupCache = $null
    [void](Invoke-Repair -Plan $plan -Backup $bk -Do $do -Verify $vf)
    $Script:StartupCache = $null
}
function Repair-FlushDns {
    $n0 = @(Get-DnsClientCache -ErrorAction SilentlyContinue).Count
    $out = 'NEEDS REVIEW'; $evi = ("No DNS failure was observed in this session; cache holds {0} entries" -f $n0)
    if ($Script:LastLevel -eq 'DNS-FAIL') { $out = 'SAFE CANDIDATE'; $evi = ("Last connectivity test showed DNS-FAIL while external IPs worked; cache holds {0} entries" -f $n0) }
    $plan = @{ Title = 'Flush DNS resolver cache'; Issue = 'Possible stale or negative DNS cache'; Evidence = $evi; Action = 'Run Clear-DnsClientCache'; Target = 'Windows DNS client cache (memory only)'; Effect = 'Cached name lookups are discarded and re-resolved on demand. No side effects beyond a brief first-lookup delay.'; Outcome = $out; Admin = $true; Recovery = 'Not needed: the cache rebuilds automatically' }
    $do = { Clear-DnsClientCache -ErrorAction Stop }
    $vf = { $n1 = @(Get-DnsClientCache -ErrorAction SilentlyContinue).Count; [pscustomobject]@{ Ok = ($n1 -lt $n0 -or $n0 -eq 0); Info = ("cache entries {0} -> {1}" -f $n0, $n1) } }
    [void](Invoke-Repair -Plan $plan -Backup $null -Do $do -Verify $vf)
}
function Repair-Temp {
    Head 'CLEAN OLD TEMP FILES (moved to quarantine, not deleted)'
    $days = Ask-Int ' Only files not modified for at least how many days? [7]' 7
    $cut = (Get-Date).AddDays(-$days)
    Say ' Scanning your user temp folder...' DarkGray
    $cand = New-Object System.Collections.ArrayList
    foreach ($f in @(Get-ChildItem -LiteralPath $env:TEMP -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cut })) {
        $locked = $false; try { $fs = [IO.File]::Open($f.FullName, 'Open', 'ReadWrite', 'None'); $fs.Close() } catch { $locked = $true }
        if (-not $locked) { [void]$cand.Add($f) }
    }
    if (-not $cand.Count) { Say ' No unlocked temp files older than that.' Green; Pause-Menu; return }
    $tot = ($cand | Measure-Object Length -Sum).Sum
    Say (" {0} files, {1} total, not locked, in {2}" -f $cand.Count, (Fmt-Bytes $tot), $env:TEMP)
    Say ' Largest:' DarkGray; $cand | Sort-Object Length -Descending | Select-Object -First 8 | ForEach-Object { Say ("   {0,10}  {1}" -f (Fmt-Bytes $_.Length), $_.FullName) DarkGray }
    $max = Ask-Int ' Quarantine how many files (largest first, max 200)? [50]' 50
    if ($max -lt 1) { return }; if ($max -gt 200) { $max = 200 }
    $sel = @($cand | Sort-Object Length -Descending | Select-Object -First $max)
    $sz = ($sel | Measure-Object Length -Sum).Sum
    $plan = @{ Title = 'Quarantine old temp files'; Issue = 'Old files in the user temp folder'; Evidence = ("Checks: location under %TEMP%, age >= {0} days, not locked at scan time. Limitation: an application may still expect a file." -f $days); Action = ("Move {0} files ({1}) to the NetWatch quarantine with a manifest per file" -f $sel.Count, (Fmt-Bytes $sz)); Target = ("{0} (largest {1} files older than {2} days)" -f $env:TEMP, $sel.Count, $days); Effect = 'Frees disk space on the temp volume only if quarantine is on another drive; files stay recoverable. Applications may recreate or miss a file.'; Outcome = 'SAFE CANDIDATE'; Admin = $false; Recovery = ("Each file keeps a manifest (original path, SHA-256, time, reason) in {0}" -f $Script:Dirs.Quarantine) }
    $script:okc = 0; $script:failc = 0
    $do = { foreach ($f in $sel) { try { $r = Move-ToQuarantine $f.FullName ("temp file older than $days days"); if ($r.Ok) { $script:okc++ } else { $script:failc++ } } catch { $script:failc++ } } }
    $vf = { [pscustomobject]@{ Ok = ($script:okc -gt 0 -and $script:failc -eq 0); Info = ("{0} moved and hash-verified, {1} failed" -f $script:okc, $script:failc) } }
    [void](Invoke-Repair -Plan $plan -Backup $null -Do $do -Verify $vf)
}
function Repair-QuarantineFile {
    $p = (Read-Host ' Full path of the file to quarantine').Trim('"', ' ')
    if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Leaf)) { Say ' File not found.' Yellow; Pause-Menu; return }
    $cls = Get-Classification -Path $p -Kind 'File' -Name (Split-Path $p -Leaf)
    $inUse = $false; try { $fs = [IO.File]::Open($p, 'Open', 'ReadWrite', 'None'); $fs.Close() } catch { $inUse = $true }
    $plan = @{ Title = 'Quarantine file'; Issue = 'File selected by the user for review'; Evidence = (($cls.Evidence + $cls.Limitations) -join ' / ') + $(if ($inUse) { ' / File is currently in use or locked' } else { '' }); Action = 'Move the file to the NetWatch quarantine (renamed .qfile so it cannot run) with a manifest'; Target = $p; Effect = 'The program or document will stop working until restored. Nothing is permanently deleted.'; Outcome = $cls.Outcome; Admin = $false; Recovery = 'Manifest with original path and SHA-256; restore via option 7' }
    $script:qr = $null
    $do = { $script:qr = Move-ToQuarantine $p 'user-selected quarantine' }
    $vf = { [pscustomobject]@{ Ok = ($script:qr -and $script:qr.Ok); Info = $(if ($script:qr) { "moved, hash verified (id $($script:qr.Id))" } else { 'move failed' }) } }
    if ($inUse) { Say ' The file is locked/in use; moving it may fail.' Yellow }
    [void](Invoke-Repair -Plan $plan -Backup $null -Do $do -Verify $vf)
}
function Repair-StopProcess {
    $id = Ask-Int ' PID of the process to stop' -1
    $cp = Get-CimInstance Win32_Process -Filter "ProcessId=$id" -ErrorAction SilentlyContinue
    $gp = Get-Process -Id $id -ErrorAction SilentlyContinue
    if (-not $cp -or -not $gp) { Say ' Process not found.' Yellow; Pause-Menu; return }
    Say ' Measuring CPU for 5 seconds to verify the runaway condition...' DarkGray
    $c0 = $gp.TotalProcessorTime.TotalSeconds; Start-Sleep -Seconds 5
    $gp.Refresh(); $c1 = $gp.TotalProcessorTime.TotalSeconds
    $corePct = [math]::Round(($c1 - $c0) / 5 * 100, 0)
    $resp = $true; try { $resp = $gp.Responding } catch {}
    $ws = $gp.WorkingSet64
    $evid = @(); if ($corePct -ge 80) { $evid += "uses {0}% of one CPU core" -f $corePct }; if (-not $resp) { $evid += 'window not responding' }; if ($ws -ge 2GB) { $evid += "working set {0}" -f (Fmt-Bytes $ws) }
    $cls = Get-Classification -Path $cp.ExecutablePath -Kind 'Process' -Name $cp.Name
    if ($evid.Count -eq 0) { Say (" Not verified as runaway (CPU {0}% of a core, responding, memory {1}). NetWatch only offers this for verified runaway processes; use Task Manager if you still want to end it." -f $corePct, (Fmt-Bytes $ws)) Yellow; Pause-Menu; return }
    $plan = @{ Title = 'Stop runaway process'; Issue = ("{0} (PID {1}) appears runaway" -f $cp.Name, $id); Evidence = ($evid -join '; ') + ' / ' + ($cls.Evidence -join ' / '); Action = 'Stop-Process (ends the process; unsaved work in it is lost)'; Target = ("{0} PID {1} {2}" -f $cp.Name, $id, $cp.ExecutablePath); Effect = 'The program closes immediately without saving. It is not removed or disabled.'; Outcome = $cls.Outcome; Admin = $false; Recovery = 'Not recoverable for unsaved data; the program can be started again' }
    if ($cls.Outcome -ne 'PROTECTED') { $t = Read-Host (" Type the process name '{0}' to continue (anything else cancels)" -f $cp.Name); if ($t -ne $cp.Name) { Say ' Cancelled.' Green; Pause-Menu; return } }
    $do = { Stop-Process -Id $id -ErrorAction Stop }
    $vf = { Start-Sleep -Seconds 1; $g = Get-Process -Id $id -ErrorAction SilentlyContinue; [pscustomobject]@{ Ok = (-not $g); Info = $(if ($g) { 'process still running' } else { 'process ended' }) } }
    [void](Invoke-Repair -Plan $plan -Backup $null -Do $do -Verify $vf)
}
function Repair-Defender {
    $before = $null; try { $before = (Get-MpComputerStatus -ErrorAction Stop).QuickScanEndTime } catch {}
    $plan = @{ Title = 'Windows Defender quick scan'; Issue = 'Optional malware check'; Evidence = 'User request (read-only scan; remediation follows Defender policy)'; Action = 'Start-MpScan -ScanType QuickScan'; Target = 'Windows Defender'; Effect = 'Uses CPU/disk for several minutes. Defender itself may quarantine detections according to its own settings.'; Outcome = 'NEEDS REVIEW'; Admin = $true; Recovery = 'Defender protection history lets you restore items' }
    $do = { Say ' Scanning (this can take several minutes)...' DarkGray; Start-MpScan -ScanType QuickScan -ErrorAction Stop }
    $vf = { $after = $null; try { $after = (Get-MpComputerStatus -ErrorAction Stop).QuickScanEndTime } catch {}; $th = @(); try { $th = @(Get-MpThreatDetection -ErrorAction Stop) } catch {}; [pscustomobject]@{ Ok = ($after -and $after -ne $before); Info = ("scan finished {0}; detections in history: {1}" -f $after, $th.Count) } }
    [void](Invoke-Repair -Plan $plan -Backup $null -Do $do -Verify $vf)
}
function Repair-SfcDism {
    Head 'SFC / DISM'
    Say ' [1] Read-only checks: sfc /verifyonly + DISM /CheckHealth + DISM /ScanHealth'
    Say ' [2] REPAIR: DISM /RestoreHealth then sfc /scannow (modifies Windows; may contact Windows Update)'
    $c = (Read-Host ' Select (Enter = back)').Trim()
    if ($c -eq '1') {
        $plan = @{ Title = 'Read-only system integrity checks'; Issue = 'Verify Windows component store and system files'; Evidence = 'User request'; Action = 'sfc /verifyonly; DISM /Online /Cleanup-Image /CheckHealth and /ScanHealth'; Target = 'Windows system files and component store (read-only)'; Effect = 'Takes 10-30 minutes; changes nothing'; Outcome = 'NEEDS REVIEW'; Admin = $true; Recovery = 'Not needed (read-only)' }
        $script:sfcRes = ''
        $do = { $a = ((& sfc /verifyonly 2>&1) -join ' ') -replace "`0", ''; $b = ((& DISM /Online /Cleanup-Image /CheckHealth 2>&1) -join ' '); $d = ((& DISM /Online /Cleanup-Image /ScanHealth 2>&1) -join ' ')
            $script:sfcRes = ("SFC: {0} | DISM check: {1} | DISM scan: {2}" -f $(if ($a -match 'did not find') { 'clean' } elseif ($a -match 'found integrity') { 'VIOLATIONS' } else { 'unclear' }), $(if ($b -match 'No component store corruption') { 'no corruption' } elseif ($b -match 'repairable') { 'REPAIRABLE corruption' } else { 'unclear' }), $(if ($d -match 'No component store corruption') { 'no corruption' } elseif ($d -match 'repairable') { 'REPAIRABLE corruption' } else { 'unclear' })) }
        $vf = { [pscustomobject]@{ Ok = [bool]$script:sfcRes; Info = $script:sfcRes } }
        [void](Invoke-Repair -Plan $plan -Backup $null -Do $do -Verify $vf)
    } elseif ($c -eq '2') {
        Say ' No restore point is claimed unless one is created and verified (use option 1 of the Repair Center first).' Yellow
        $plan = @{ Title = 'DISM RestoreHealth + SFC scannow'; Issue = 'Repair of corrupted Windows components'; Evidence = 'Only run this if the read-only checks reported corruption'; Action = 'DISM /Online /Cleanup-Image /RestoreHealth then sfc /scannow'; Target = 'Windows component store and protected system files'; Effect = 'Replaces damaged system files from Windows sources; may download from Windows Update; can take 30+ minutes'; Outcome = 'NEEDS REVIEW'; Admin = $true; Recovery = 'Create a restore point first (option 1); Windows keeps its own CBS logs' }
        $script:rr = ''
        $do = { $a = ((& DISM /Online /Cleanup-Image /RestoreHealth 2>&1) -join ' '); $b = ((& sfc /scannow 2>&1) -join ' ') -replace "`0", ''; $script:rr = ("DISM: {0} | SFC: {1}" -f $(if ($a -match 'completed successfully') { 'completed' } else { 'did not report success' }), $(if ($b -match 'did not find') { 'clean' } elseif ($b -match 'successfully repaired') { 'repaired' } elseif ($b -match 'unable to fix') { 'UNABLE to fix some files' } else { 'unclear' })) }
        $vf = { $a = ((& sfc /verifyonly 2>&1) -join ' ') -replace "`0", ''; [pscustomobject]@{ Ok = ($a -match 'did not find any integrity violations'); Info = ($script:rr + ' | re-verify: ' + $(if ($a -match 'did not find') { 'clean' } else { 'violations remain or unclear' })) } }
        [void](Invoke-Repair -Plan $plan -Backup $null -Do $do -Verify $vf)
    }
}
function Repair-RestorePoint {
    $plan = @{ Title = 'Create system restore point'; Issue = 'Recovery option before risky changes'; Evidence = 'User request'; Action = 'Checkpoint-Computer'; Target = 'System Protection on the system drive'; Effect = 'Creates a restore point if System Protection is enabled (Windows allows one per 24h by default)'; Outcome = 'NEEDS REVIEW'; Admin = $true; Recovery = 'This IS the recovery mechanism; existence is verified afterwards' }
    $stamp = Get-Date
    $do = { Checkpoint-Computer -Description 'NetWatch checkpoint' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop }
    $vf = { $rp = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Where-Object { $_.Description -eq 'NetWatch checkpoint' } | Sort-Object SequenceNumber -Descending | Select-Object -First 1); $ok = ($rp.Count -gt 0 -and ([Management.ManagementDateTimeConverter]::ToDateTime($rp[0].CreationTime) -gt $stamp.AddMinutes(-2))); [pscustomobject]@{ Ok = $ok; Info = $(if ($ok) { "restore point #$($rp[0].SequenceNumber) exists" } else { 'no new restore point found (System Protection may be off or throttled)' }) } }
    [void](Invoke-Repair -Plan $plan -Backup $null -Do $do -Verify $vf)
}
function Restore-Items {
    Head 'RESTORE QUARANTINED FILES / STARTUP ENTRIES'
    $mf = @(Get-ChildItem -LiteralPath $Script:Dirs.Quarantine -Filter '*.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    $dis = @(); if (Test-Path $Script:DisabledFile) { try { $dis = @(Get-Content $Script:DisabledFile -Raw | ConvertFrom-Json) } catch {} }
    $i = 0; $map = @{}
    Say ' Quarantined files:' White
    foreach ($f in $mf) { $m = Get-Content $f.FullName -Raw | ConvertFrom-Json; $i++; $map[$i] = @('file', $m); Say ("  [{0}] {1}  ({2}, {3})" -f $i, $m.OriginalPath, (Fmt-Bytes $m.Size), $m.QuarantinedAt) }
    Say ' Disabled startup entries:' White
    foreach ($d in $dis) { $i++; $map[$i] = @('reg', $d); Say ("  [{0}] {1} : {2}  (disabled {3})" -f $i, $d.RegPath, $d.Name, $d.Time) }
    if ($i -eq 0) { Say ' Nothing to restore.' Green; Pause-Menu; return }
    $n = Ask-Int ' Number to restore (0 = cancel)' 0
    if (-not $map.ContainsKey($n)) { return }
    if ($map[$n][0] -eq 'file') {
        $m = $map[$n][1]
        if (Test-Path -LiteralPath $m.OriginalPath) { Say ' Original path already exists; refusing to overwrite.' Yellow; Pause-Menu; return }
        $plan = @{ Title = 'Restore quarantined file'; Issue = 'User wants the file back'; Evidence = ("Manifest {0}; original hash {1}" -f $m.Id, $m.Sha256); Action = 'Move the stored file back to its original location'; Target = $m.OriginalPath; Effect = 'The file is available again (and may run again)'; Outcome = 'NEEDS REVIEW'; Admin = $false; Recovery = 'Can be quarantined again' }
        $do = { $dir = Split-Path $m.OriginalPath; if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }; Move-Item -LiteralPath $m.StoredAs -Destination $m.OriginalPath -ErrorAction Stop }
        $vf = { $ok = (Test-Path -LiteralPath $m.OriginalPath) -and ((Get-FileHash -LiteralPath $m.OriginalPath -Algorithm SHA256).Hash -eq $m.Sha256); [pscustomobject]@{ Ok = $ok; Info = $(if ($ok) { 'restored and hash matches the manifest' } else { 'restore not verified' }) } }
        [void](Invoke-Repair -Plan $plan -Backup $null -Do $do -Verify $vf)
        if (Test-Path -LiteralPath $m.OriginalPath) { Remove-Item ($m.StoredAs + '.json') -Force -ErrorAction SilentlyContinue }
    } else {
        $d = $map[$n][1]
        $plan = @{ Title = 'Re-enable startup entry'; Issue = 'User wants the entry back'; Evidence = ("Saved on {0}" -f $d.Time); Action = 'Re-create the Run value'; Target = ("{0} value '{1}' = {2}" -f $d.RegPath, $d.Name, $d.Value); Effect = 'The program starts at logon again'; Outcome = 'NEEDS REVIEW'; Admin = ($d.RegPath -like 'HKLM:*'); Recovery = 'Can be disabled again' }
        $do = { New-ItemProperty -Path $d.RegPath -Name $d.Name -Value $d.Value -PropertyType $d.Kind -Force -ErrorAction Stop | Out-Null }
        $vf = { $v = (Get-ItemProperty -Path $d.RegPath -Name $d.Name -ErrorAction SilentlyContinue).($d.Name); [pscustomobject]@{ Ok = ($v -eq $d.Value); Info = $(if ($v -eq $d.Value) { 'value present and equal to the saved data' } else { 'value missing or different' }) } }
        if (Invoke-Repair -Plan $plan -Backup $null -Do $do -Verify $vf) { $keep = @($dis | Where-Object { -not ($_.RegPath -eq $d.RegPath -and $_.Name -eq $d.Name) }); ConvertTo-Json -InputObject @($keep) | Set-Content $Script:DisabledFile -Encoding UTF8 }
        $Script:StartupCache = $null
    }
}
function Show-TrafficAdvice {
    Head 'RECOMMENDATIONS TO REDUCE UNNECESSARY BACKGROUND TRAFFIC'
    Say ' Based on measured or observed data only. NetWatch changes none of these settings.' DarkGray
    $cats = @{}
    if ($Script:LastBw) { foreach ($r in $Script:LastBw.Rows) { $t = $r.Download + $r.Upload; if ($cats.ContainsKey($r.Category)) { $cats[$r.Category] += $t } else { $cats[$r.Category] = $t } }; Say (" Source: ETW capture of {0:HH:mm:ss} (measured)" -f $Script:LastBw.Time) Green }
    else { Say ' No per-process capture yet; using current connection counts (indicators, not bandwidth).' Yellow
        $pt = Get-ProcTable
        foreach ($c in @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1)' })) { $p = $pt[[int]$c.OwningProcess]; if ($p) { $k = Get-Categ $p.Name $p.ExecutablePath; if ($cats.ContainsKey($k)) { $cats[$k]++ } else { $cats[$k] = 1 } } } }
    $adv = @{
        'Update service' = 'Windows Update/Delivery Optimization: Settings > Windows Update > Advanced > Delivery Optimization (limit bandwidth or disable uploads to other PCs); set the connection as metered to defer large updates.'
        'Cloud sync' = 'Pause sync in the app, choose selective folders, or schedule syncing outside work hours.'
        'Game launcher' = 'Disable auto-updates/background downloads in the launcher settings.'
        'Backup' = 'Schedule backups at night or throttle upload speed in the backup app.'
        'Peer-to-peer' = 'Limit upload/download rates or stop seeding when you need the connection.'
        'Download manager' = 'Pause queued downloads or set a speed limit.'
        'Browser' = 'Close unused tabs/streaming, pause extensions that sync, check for large downloads in the downloads page.'
        'Streaming/communication' = 'Lower video quality or close apps left streaming in the background.'
    }
    $any = $false
    foreach ($k in ($cats.Keys | Sort-Object { $cats[$_] } -Descending)) { if ($adv.ContainsKey($k)) { $any = $true; Say (" {0}: {1}" -f $k, $adv[$k]) } }
    if (-not $any) { Say ' No recognised background-traffic categories were seen.' Green }
    Say ' Also: review startup apps (menu 3) and disable ones you do not need via Task Manager > Startup.' DarkGray
    Pause-Menu
}
function Show-Repair {
    while ($true) {
        Head 'REPAIR, CLEANUP AND OPTIMIZATION CENTER'
        Say ' Every action: evidence > plan > classification > admin check > recovery step > explicit YES > execute > verify > log.' DarkGray
        Say ' Never automatic. Suspicious files are quarantined (recoverable), never permanently deleted by NetWatch.' DarkGray
        Say ''
        Say '  1. Create a system restore point (verified afterwards)      6. Quarantine a file (recoverable)'
        Say '  2. Flush DNS resolver cache                                 7. Restore a quarantined file / startup entry'
        Say '  3. Clean old temp files (moved to quarantine)               8. Windows Defender quick scan'
        Say '  4. Disable a Run-key startup entry (reversible)             9. SFC / DISM checks and repair'
        Say '  5. Stop a verified runaway process                         10. Recommendations to reduce background traffic'
        Say '  B. Back'
        $c = (Read-Host ' Select').Trim().ToUpper()
        switch ($c) {
            '1' { Repair-RestorePoint } '2' { Repair-FlushDns } '3' { Repair-Temp } '4' { Repair-DisableStartup } '5' { Repair-StopProcess }
            '6' { Repair-QuarantineFile } '7' { Restore-Items } '8' { Repair-Defender } '9' { Repair-SfcDism } '10' { Show-TrafficAdvice } 'B' { return }
        }
    }
}

# --------------------------------------------------------- Module L: reports
function Export-Report {
    $f = Join-Path $Script:Dirs.Reports ("netwatch_report_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    Say ' Collecting a connectivity snapshot...' DarkGray
    $s = Get-ConnState
    $os = Get-CimInstance Win32_OperatingSystem
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("NETWATCH REPORT  v$($Script:Ver)   generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine("Contains local IP addresses, user name and file paths: review before sharing.")
    [void]$sb.AppendLine(("System: {0} build {1}; elevated={2}; session {3}" -f $os.Caption, $os.BuildNumber, $Script:IsAdmin, $Script:SessionId))
    [void]$sb.AppendLine(('-' * 70)); [void]$sb.AppendLine('CONNECTIVITY SNAPSHOT (measured now)')
    [void]$sb.AppendLine(("Level {0}: {1}" -f $s.Level, (Get-LevelText $s.Level)))
    [void]$sb.AppendLine(("Adapter {0} [{1}] IP {2} GW {3} DNS {4} gwPing {5}ms extPing {6}ms dns {7}ms" -f $s.Adapter, $s.Kind, $s.Ip, $s.Gateway, ($s.Dns -join ','), $s.GwMs, $s.ExtMs, $s.DnsMs))
    if ($Script:LastBw) { [void]$sb.AppendLine(('-' * 70)); [void]$sb.AppendLine(("PER-PROCESS BANDWIDTH (ETW, directly measured, {0}s at {1})" -f $Script:LastBw.Seconds, $Script:LastBw.Time)); foreach ($r in ($Script:LastBw.Rows | Select-Object -First 15)) { [void]$sb.AppendLine(("{0} pid {1}: down {2}, up {3} {4}" -f $r.Process, $r.PID, (Fmt-Bytes $r.Download), (Fmt-Bytes $r.Upload), $r.Note)) } }
    [void]$sb.AppendLine(('-' * 70)); [void]$sb.AppendLine("FINDINGS ($($Script:Findings.Count))")
    foreach ($x in $Script:Findings) { [void]$sb.AppendLine(("[{0}] {1} / {2} ({3}, confidence {4}) @ {5}" -f $x.Severity, $x.Module, $x.Title, $x.Status, $x.Confidence, $x.Time)); [void]$sb.AppendLine("    Evidence: $($x.Evidence)"); [void]$sb.AppendLine("    Cause: $($x.Cause)  Next: $($x.NextStep)  Repair: $($x.RepairOptions)  Classification: $($x.Outcome)") }
    [void]$sb.AppendLine(('-' * 70)); [void]$sb.AppendLine("CLASSIFICATIONS RECORDED THIS SESSION ($($Script:SessionCls.Count))")
    foreach ($c in $Script:SessionCls) { [void]$sb.AppendLine(("{0} {1} {2}: {3} {4}" -f $c.Time, $c.Kind, $c.Name, $c.Outcome, $c.Note)); [void]$sb.AppendLine("    reason: $($c.Reason)"); [void]$sb.AppendLine("    limitations: $($c.Limitations)") }
    if (Test-Path $Script:EventsCsv) {
        $ev = @(Import-Csv $Script:EventsCsv | Where-Object { $_.Session -eq $Script:SessionId })
        [void]$sb.AppendLine(('-' * 70)); [void]$sb.AppendLine("SESSION EVENTS ($($ev.Count); last 150 shown)")
        foreach ($e in ($ev | Select-Object -Last 150)) { [void]$sb.AppendLine(("{0} {1} {2}" -f $e.Time, $e.Type, $e.Detail)) }
    }
    $txt = $sb.ToString()
    $red = (Read-Host ' Redact user name and IPv4 addresses in this report? (Y/n)').Trim().ToLower()
    if ($red -ne 'n') { if ($env:USERNAME.Length -ge 3) { $txt = $txt -replace [regex]::Escape($env:USERNAME), '<user>' }; $txt = $txt -replace '\b\d{1,3}(\.\d{1,3}){3}\b', 'x.x.x.x' }
    Set-Content -Path $f -Value $txt -Encoding UTF8
    $c = Join-Path $Script:Dirs.Reports ("findings_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    if ($Script:Findings.Count) { $Script:Findings | Export-Csv $c -NoTypeInformation -Encoding UTF8 }
    Say (" Saved: {0}" -f $f) Green; if ($Script:Findings.Count) { Say (" Saved: {0}" -f $c) Green }
    Say ' WARNING: reports can contain local IPs, user names and process paths. Check before sharing with anyone.' Yellow
    Write-EventRec 'REPORT_EXPORT' $f
}
function Show-Reports {
    while ($true) {
        Head 'REPORTS AND MONITORING HISTORY'
        Say (" Data folder: {0}" -f $Script:Root) DarkGray
        Say ' [1] Generate TXT report + findings CSV (this session)'
        Say ' [2] View recent logged events (events.csv, last 40)'
        Say ' [3] View classification history (last 25)'
        Say ' [4] Export connections snapshot CSV'
        Say ' [5] Open data folder   [6] Apply log retention now   [B] Back'
        $c = (Read-Host ' Select').Trim().ToUpper()
        switch ($c) {
            '1' { Export-Report; Pause-Menu }
            '2' { if (Test-Path $Script:EventsCsv) { Show-Table (@(Import-Csv $Script:EventsCsv) | Select-Object -Last 40) @('Time', 'Type', 'Detail') } else { Say ' No events logged yet.' Yellow }; Pause-Menu }
            '3' { if (Test-Path $Script:ClsFile) { $r = @(Get-Content $Script:ClsFile | Select-Object -Last 25 | ForEach-Object { $_ | ConvertFrom-Json }); Show-Table $r @('Time', 'Kind', 'Name', 'Outcome', 'Note', 'Reason') } else { Say ' No history yet.' Yellow }; Pause-Menu }
            '4' {
                $pt = Get-ProcTable; $f = Join-Path $Script:Dirs.Reports ("connections_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
                Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object { $p = $pt[[int]$_.OwningProcess]; [pscustomobject]@{ Process = $(if ($p) { $p.Name } else { '' }); PID = $_.OwningProcess; Path = $(if ($p) { $p.ExecutablePath } else { '' }); Local = "$($_.LocalAddress):$($_.LocalPort)"; Remote = "$($_.RemoteAddress):$($_.RemotePort)"; State = $_.State } } | Export-Csv $f -NoTypeInformation -Encoding UTF8
                Say (" Saved: {0} (contains IPs and paths; review before sharing)" -f $f) Yellow; Pause-Menu
            }
            '5' { Start-Process explorer.exe $Script:Root }
            '6' { Invoke-Retention; Say ' Retention applied.' Green; Start-Sleep -Seconds 1 }
            'B' { return }
        }
    }
}

# --------------------------------------------------------------- settings
function Request-Elevation {
    if ($Script:IsAdmin) { Say ' Already running as Administrator.' Green; return }
    if (-not (Confirm-Action ' Relaunch NetWatch with Administrator rights (Windows will show a UAC prompt)?')) { return }
    try { Start-Process -FilePath $env:NW_SELF -Verb RunAs -ErrorAction Stop; Cleanup-Exit; exit 0 } catch { Say (" Elevation was cancelled or failed: {0}" -f $_.Exception.Message) Yellow; Pause-Menu }
}
function Show-Settings {
    while ($true) {
        Head 'SETTINGS AND MONITORING CONFIGURATION'
        Say (" [1] Polling interval (s)        : {0}   (1, 2, 5 or 10)" -f $Script:Cfg.IntervalSec)
        Say (" [2] Log retention (days)       : {0}" -f $Script:Cfg.RetentionDays)
        Say (" [3] Max events.csv size (MB)   : {0}" -f $Script:Cfg.MaxLogMB)
        Say (" [4] Burst alert minimum (MB/s) : {0}   and factor over recent average: {1}x" -f $Script:Cfg.BurstMBps, $Script:Cfg.BurstFactor)
        Say (" [5] Connectivity re-test every : {0} samples" -f $Script:Cfg.ConnectivityEveryTicks)
        Say ' [6] Relaunch as Administrator'
        Say ' [7] Show environment / compatibility information'
        Say ' [8] Reset settings to defaults   [B] Back'
        $c = (Read-Host ' Select').Trim().ToUpper()
        switch ($c) {
            '1' { $n = Ask-Int ' Seconds (1,2,5,10)' 0; if ($n -in 1, 2, 5, 10) { $Script:Cfg.IntervalSec = $n } }
            '2' { $n = Ask-Int ' Days (1-365)' 0; if ($n -ge 1 -and $n -le 365) { $Script:Cfg.RetentionDays = $n } }
            '3' { $n = Ask-Int ' MB (1-500)' 0; if ($n -ge 1 -and $n -le 500) { $Script:Cfg.MaxLogMB = $n } }
            '4' { $n = Ask-Int ' Minimum MB/s (1-1000)' 0; if ($n -ge 1) { $Script:Cfg.BurstMBps = $n }; $m = Ask-Int ' Factor (2-20)' 0; if ($m -ge 2 -and $m -le 20) { $Script:Cfg.BurstFactor = $m } }
            '5' { $n = Ask-Int ' Samples (5-300)' 0; if ($n -ge 5 -and $n -le 300) { $Script:Cfg.ConnectivityEveryTicks = $n } }
            '6' { Request-Elevation }
            '7' { Show-Env; Pause-Menu }
            '8' { $Script:Cfg.IntervalSec = 2; $Script:Cfg.RetentionDays = 30; $Script:Cfg.MaxLogMB = 20; $Script:Cfg.BurstMBps = 5; $Script:Cfg.BurstFactor = 4; $Script:Cfg.ConnectivityEveryTicks = 15 }
            'B' { Save-Cfg; return }
        }
        Save-Cfg
    }
}
function Show-Env {
    $os = Get-CimInstance Win32_OperatingSystem
    $b = [int]$os.BuildNumber
    $fam = 'Unsupported/unknown'; if ($b -ge 22000) { $fam = 'Windows 11' } elseif ($b -ge 10240) { $fam = 'Windows 10' }
    Say (" OS: {0} build {1} -> {2}" -f $os.Caption, $b, $fam) $(if ($fam -match 'Windows') { 'Green' } else { 'Red' })
    Say (" PowerShell {0}; elevated: {1}" -f $PSVersionTable.PSVersion, $Script:IsAdmin)
    foreach ($c in 'Get-NetTCPConnection', 'Get-NetAdapterStatistics', 'Get-ScheduledTask', 'Resolve-DnsName', 'Get-WinEvent', 'Get-MpComputerStatus', 'Get-MpThreatDetection', 'Start-MpScan', 'Get-AuthenticodeSignature') { Say ("   {0,-28} {1}" -f $c, $(if (Get-Command $c -ErrorAction SilentlyContinue) { 'available' } else { 'MISSING (related features degrade)' })) }
    foreach ($c in 'logman.exe', 'netsh.exe', 'sfc.exe', 'dism.exe', 'ipconfig.exe', 'netstat.exe', 'auditpol.exe') { Say ("   {0,-28} {1}" -f $c, $(if (Get-Command $c -ErrorAction SilentlyContinue) { 'available' } else { 'MISSING' })) }
    Say (" Data folder: {0}" -f $Script:Root)
}

# ------------------------------------------------------------------- main
function Cleanup-Exit {
    if ($Script:EtwActive) { & logman stop $Script:EtwName -ets 2>&1 | Out-Null }
    Remove-Item $Script:EtwFile -Force -ErrorAction SilentlyContinue
    Write-Log 'INFO' 'NetWatch exit'
    try { Invoke-Retention } catch {}
}
function Show-Main {
    while ($true) {
        Head ("MAIN MENU  v{0}" -f $Script:Ver)
        Say ' MONITOR > INVESTIGATE > CLASSIFY > RECOMMEND > APPROVE > REPAIR > VERIFY > REPORT' DarkGray
        Say ' Monitoring and investigation are read-only. Changes happen only in menu 9 after explicit approval.' DarkGray
        Say ''
        Say '  1. Live Internet Activity Monitor'
        Say '  2. Running Processes and Network Connections'
        Say '  3. Startup and Automatic Execution Investigation'
        Say '  4. Per-Process Bandwidth Investigation'
        Say '  5. File Activity and Download Investigation'
        Say '  6. Network and Internet Diagnostics'
        Say '  7. Security and Suspicious Activity Scan'
        Say '  8. Windows Bug and System Health Check'
        Say '  9. Repair, Cleanup, and Optimization Center'
        Say ' 10. Reports and Monitoring History'
        Say ' 11. Settings and Monitoring Configuration'
        Say ' 12. Exit'
        $c = (Read-Host "`n Select").Trim()
        switch ($c) {
            '1' { Show-LiveMenu } '2' { Show-Connections } '3' { Show-Startup } '4' { Show-Bandwidth } '5' { Show-FileActivity } '6' { Invoke-Diagnostics }
            '7' { Invoke-SecurityScan } '8' { Invoke-HealthCheck } '9' { Show-Repair } '10' { Show-Reports } '11' { Show-Settings } '12' { return }
        }
    }
}
try {
    Load-Cfg; Load-ClsHistory
    Write-Log 'INFO' ("NetWatch {0} start; elevated={1}" -f $Script:Ver, $Script:IsAdmin)
    $b = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber
    if ($b -lt 10240 -or $PSVersionTable.PSVersion.Major -lt 5) {
        Say ' This tool supports Windows 10/11 with Windows PowerShell 5.1. Some features may not work on this system.' Yellow
        Pause-Menu
    }
    Show-Main
} finally {
    Cleanup-Exit
}
exit 0
