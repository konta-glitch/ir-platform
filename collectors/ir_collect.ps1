<#
.SYNOPSIS
    IR Collector — Standalone forensic artifact collector for Windows
    No dependencies, no installation, no Velociraptor needed

.DESCRIPTION
    Collects forensic artifacts according to IR best practices:
    - Running processes with hashes and command lines
    - Network connections and listening ports
    - DNS cache, ARP table, network interfaces
    - Services, scheduled tasks, autorun entries
    - Event logs (Security, System, PowerShell, Sysmon, Defender)
    - Prefetch files, recent file activity
    - Browser history, RDP cache
    - Installed software, user accounts
    - File system timeline (recently modified files)

    Output: Timestamped ZIP file with JSON data

.USAGE
    Right-click → Run as Administrator (recommended)
    Or: powershell -ExecutionPolicy Bypass -File .\ir_collect.ps1
    Or: powershell -ExecutionPolicy Bypass -File .\ir_collect.ps1 -Quick
#>

param(
    [switch]$Quick,        # Quick triage (skip heavy artifacts)
    [switch]$NoZip,        # Don't compress, leave folder
    [string]$OutputDir = "",# Custom output directory
    [string]$Password = "infected"  # ZIP password (requires 7z)
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

# ═══════════════════════════════════════════
# Setup
# ═══════════════════════════════════════════

$Hostname = $env:COMPUTERNAME
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$CollectionName = "IR_${Hostname}_${Timestamp}"

if ($OutputDir -eq "") {
    $OutputDir = Join-Path $env:TEMP $CollectionName
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host ""
Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║        IR Collector (Standalone)          ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Host:      $Hostname"
Write-Host "  Time:      $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "  Admin:     $IsAdmin"
Write-Host "  Output:    $OutputDir"
Write-Host "  Mode:      $(if ($Quick) {'Quick triage'} else {'Full collection'})"
Write-Host ""

if (-not $IsAdmin) {
    Write-Host "  [!] Not running as admin — some artifacts will be limited" -ForegroundColor Yellow
    Write-Host ""
}

function Collect {
    param([string]$Name, [scriptblock]$Action)
    Write-Host "  [*] Collecting: $Name..." -ForegroundColor Gray -NoNewline
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $result = & $Action
        $outPath = Join-Path $OutputDir "$Name.json"
        $result | ConvertTo-Json -Depth 10 -Compress | Out-File -Encoding UTF8 $outPath
        $count = if ($result -is [array]) { $result.Count } else { 1 }
        $sw.Stop()
        Write-Host " OK ($count items, $($sw.Elapsed.TotalSeconds.ToString('0.0'))s)" -ForegroundColor Green
    }
    catch {
        $sw.Stop()
        Write-Host " FAILED: $($_.Exception.Message)" -ForegroundColor Red
        @{error = $_.Exception.Message; artifact = $Name} | 
            ConvertTo-Json | Out-File -Encoding UTF8 (Join-Path $OutputDir "$Name.error.json")
    }
}

# ═══════════════════════════════════════════
# System info
# ═══════════════════════════════════════════

Collect "system_info" {
    @{
        hostname = $env:COMPUTERNAME
        domain = $env:USERDOMAIN
        username = $env:USERNAME
        os = (Get-CimInstance Win32_OperatingSystem).Caption
        os_version = (Get-CimInstance Win32_OperatingSystem).Version
        os_build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
        architecture = $env:PROCESSOR_ARCHITECTURE
        install_date = (Get-CimInstance Win32_OperatingSystem).InstallDate
        last_boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        timezone = (Get-TimeZone).Id
        collection_time = (Get-Date -Format "o")
        is_admin = $IsAdmin
        ip_addresses = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" }).IPAddress
    }
}

# ═══════════════════════════════════════════
# Live system state
# ═══════════════════════════════════════════

Collect "processes" {
    Get-CimInstance Win32_Process | ForEach-Object {
        $hash = ""
        if ($_.ExecutablePath -and (Test-Path $_.ExecutablePath)) {
            $hash = (Get-FileHash $_.ExecutablePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        }
        @{
            pid = $_.ProcessId
            ppid = $_.ParentProcessId
            name = $_.Name
            path = $_.ExecutablePath
            cmdline = $_.CommandLine
            user = (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.ProcessId)" | 
                    Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue).User
            create_time = $_.CreationDate
            sha256 = $hash
            working_set_mb = [math]::Round($_.WorkingSetSize / 1MB, 1)
        }
    }
}

Collect "network_connections" {
    Get-NetTCPConnection | Where-Object { $_.State -ne "TimeWait" } | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        @{
            local_address = $_.LocalAddress
            local_port = $_.LocalPort
            remote_address = $_.RemoteAddress
            remote_port = $_.RemotePort
            state = $_.State.ToString()
            pid = $_.OwningProcess
            process_name = $proc.Name
            process_path = $proc.Path
        }
    }
}

Collect "listening_ports" {
    Get-NetTCPConnection -State Listen | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        @{
            address = $_.LocalAddress
            port = $_.LocalPort
            pid = $_.OwningProcess
            process = $proc.Name
            path = $proc.Path
        }
    }
}

Collect "dns_cache" {
    Get-DnsClientCache | ForEach-Object {
        @{
            name = $_.Entry
            type = $_.Type.ToString()
            data = $_.Data
            ttl = $_.TimeToLive
        }
    }
}

Collect "arp_table" {
    Get-NetNeighbor | ForEach-Object {
        @{
            ip = $_.IPAddress
            mac = $_.LinkLayerAddress
            state = $_.State.ToString()
            interface = $_.InterfaceAlias
        }
    }
}

Collect "network_interfaces" {
    Get-NetAdapter | ForEach-Object {
        $ip = Get-NetIPAddress -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue
        @{
            name = $_.Name
            description = $_.InterfaceDescription
            status = $_.Status
            mac = $_.MacAddress
            speed_mbps = $_.LinkSpeed
            ipv4 = ($ip | Where-Object AddressFamily -eq "IPv4").IPAddress
            ipv6 = ($ip | Where-Object AddressFamily -eq "IPv6").IPAddress
        }
    }
}

# ═══════════════════════════════════════════
# Persistence
# ═══════════════════════════════════════════

Collect "services" {
    Get-CimInstance Win32_Service | ForEach-Object {
        @{
            name = $_.Name
            display_name = $_.DisplayName
            state = $_.State
            start_mode = $_.StartMode
            path = $_.PathName
            account = $_.StartName
            description = $_.Description
        }
    }
}

Collect "scheduled_tasks" {
    Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | ForEach-Object {
        $info = Get-ScheduledTaskInfo $_.TaskName -ErrorAction SilentlyContinue
        @{
            name = $_.TaskName
            path = $_.TaskPath
            state = $_.State.ToString()
            author = $_.Author
            description = $_.Description
            action = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "; "
            last_run = $info.LastRunTime
            next_run = $info.NextRunTime
            last_result = $info.LastTaskResult
        }
    }
}

Collect "autoruns" {
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    $results = @()
    foreach ($p in $paths) {
        if (Test-Path $p) {
            $props = Get-ItemProperty $p -ErrorAction SilentlyContinue
            foreach ($name in $props.PSObject.Properties.Name) {
                if ($name -notlike "PS*") {
                    $results += @{
                        location = $p
                        name = $name
                        value = $props.$name
                    }
                }
            }
        }
    }
    # Startup folder
    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($sp in $startupPaths) {
        if (Test-Path $sp) {
            Get-ChildItem $sp -ErrorAction SilentlyContinue | ForEach-Object {
                $results += @{
                    location = $sp
                    name = $_.Name
                    value = $_.FullName
                }
            }
        }
    }
    $results
}

# ═══════════════════════════════════════════
# Event Logs
# ═══════════════════════════════════════════

Collect "eventlog_security" {
    $filter = @{
        LogName = 'Security'
        ID = @(4624,4625,4634,4648,4672,4688,4697,4698,4720,4722,4723,4724,4728,4732,4756,7045)
    }
    if ($Quick) { $filter["StartTime"] = (Get-Date).AddDays(-1) }
    else { $filter["StartTime"] = (Get-Date).AddDays(-7) }

    Get-WinEvent -FilterHashtable $filter -MaxEvents 5000 | ForEach-Object {
        @{
            time = $_.TimeCreated.ToString("o")
            id = $_.Id
            level = $_.LevelDisplayName
            provider = $_.ProviderName
            message = $_.Message.Substring(0, [Math]::Min($_.Message.Length, 500))
        }
    }
}

Collect "eventlog_system" {
    $filter = @{
        LogName = 'System'
        Level = @(1,2,3)  # Critical, Error, Warning
        StartTime = if ($Quick) { (Get-Date).AddDays(-1) } else { (Get-Date).AddDays(-7) }
    }
    Get-WinEvent -FilterHashtable $filter -MaxEvents 2000 | ForEach-Object {
        @{
            time = $_.TimeCreated.ToString("o")
            id = $_.Id
            level = $_.LevelDisplayName
            provider = $_.ProviderName
            message = $_.Message.Substring(0, [Math]::Min($_.Message.Length, 500))
        }
    }
}

Collect "eventlog_powershell" {
    $filter = @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        ID = @(4103,4104)  # Script block logging
        StartTime = if ($Quick) { (Get-Date).AddDays(-1) } else { (Get-Date).AddDays(-7) }
    }
    Get-WinEvent -FilterHashtable $filter -MaxEvents 2000 | ForEach-Object {
        @{
            time = $_.TimeCreated.ToString("o")
            id = $_.Id
            message = $_.Message.Substring(0, [Math]::Min($_.Message.Length, 1000))
        }
    }
}

if (-not $Quick) {
    Collect "eventlog_sysmon" {
        $filter = @{
            LogName = 'Microsoft-Windows-Sysmon/Operational'
            StartTime = (Get-Date).AddDays(-3)
        }
        Get-WinEvent -FilterHashtable $filter -MaxEvents 5000 | ForEach-Object {
            @{
                time = $_.TimeCreated.ToString("o")
                id = $_.Id
                message = $_.Message.Substring(0, [Math]::Min($_.Message.Length, 1000))
            }
        }
    }

    Collect "eventlog_defender" {
        $filter = @{
            LogName = 'Microsoft-Windows-Windows Defender/Operational'
            StartTime = (Get-Date).AddDays(-30)
        }
        Get-WinEvent -FilterHashtable $filter -MaxEvents 500 | ForEach-Object {
            @{
                time = $_.TimeCreated.ToString("o")
                id = $_.Id
                level = $_.LevelDisplayName
                message = $_.Message.Substring(0, [Math]::Min($_.Message.Length, 500))
            }
        }
    }
}

if (-not $Quick) {
    Collect "eventlog_rdp" {
        $filter = @{
            LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
            StartTime = (Get-Date).AddDays(-30)
        }
        Get-WinEvent -FilterHashtable $filter -MaxEvents 1000 | ForEach-Object {
            @{ time = $_.TimeCreated.ToString("o"); id = $_.Id; message = $_.Message.Substring(0, [Math]::Min($_.Message.Length, 500)) }
        }
    }

    Collect "eventlog_taskscheduler" {
        $filter = @{
            LogName = 'Microsoft-Windows-TaskScheduler/Operational'
            ID = @(106, 140, 141, 200, 201)
            StartTime = (Get-Date).AddDays(-7)
        }
        Get-WinEvent -FilterHashtable $filter -MaxEvents 1000 | ForEach-Object {
            @{ time = $_.TimeCreated.ToString("o"); id = $_.Id; message = $_.Message.Substring(0, [Math]::Min($_.Message.Length, 500)) }
        }
    }

    Collect "eventlog_wmi" {
        $filter = @{
            LogName = 'Microsoft-Windows-WMI-Activity/Operational'
            StartTime = (Get-Date).AddDays(-7)
        }
        Get-WinEvent -FilterHashtable $filter -MaxEvents 500 | ForEach-Object {
            @{ time = $_.TimeCreated.ToString("o"); id = $_.Id; message = $_.Message.Substring(0, [Math]::Min($_.Message.Length, 500)) }
        }
    }

    Collect "eventlog_firewall" {
        $fwLog = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
        if (Test-Path $fwLog) {
            Get-Content $fwLog -Tail 500 | Where-Object { $_ -notmatch '^#' } | ForEach-Object {
                @{ line = $_ }
            }
        }
    }
}

# ═══════════════════════════════════════════
# Execution evidence
# ═══════════════════════════════════════════

if (-not $Quick) {
    Collect "prefetch" {
        $pfPath = "C:\Windows\Prefetch"
        if (Test-Path $pfPath) {
            Get-ChildItem $pfPath -Filter "*.pf" | ForEach-Object {
                @{
                    name = $_.Name
                    size = $_.Length
                    created = $_.CreationTime.ToString("o")
                    modified = $_.LastWriteTime.ToString("o")
                    accessed = $_.LastAccessTime.ToString("o")
                }
            }
        }
    }

    Collect "amcache" {
        $amPath = "C:\Windows\AppCompat\Programs\Amcache.hve"
        if (Test-Path $amPath) {
            @{
                exists = $true
                path = $amPath
                size = (Get-Item $amPath).Length
                modified = (Get-Item $amPath).LastWriteTime.ToString("o")
                note = "Raw hive collected — parse with AmcacheParser or RegRipper"
            }
        }
    }

    Collect "shimcache" {
        try {
            $shimKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
            if (Test-Path $shimKey) {
                $data = (Get-ItemProperty $shimKey -Name AppCompatCache -ErrorAction Stop).AppCompatCache
                @{
                    exists = $true
                    data_size = $data.Length
                    note = "Raw AppCompatCache data — parse with ShimCacheParser"
                }
            }
        } catch { @{ error = $_.Exception.Message } }
    }

    Collect "userassist" {
        $uaPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        if (Test-Path $uaPath) {
            $results = @()
            Get-ChildItem $uaPath -ErrorAction SilentlyContinue | ForEach-Object {
                $guid = $_.PSChildName
                $countKey = Join-Path $_.PSPath "Count"
                if (Test-Path $countKey) {
                    $props = Get-ItemProperty $countKey -ErrorAction SilentlyContinue
                    foreach ($name in $props.PSObject.Properties.Name) {
                        if ($name -notlike "PS*") {
                            # ROT13 decode the name
                            $decoded = $name -creplace '[A-Za-z]', { $m = $_.Value; $c = [int][char]$m; if ($c -ge 65 -and $c -le 90) { [char](($c - 65 + 13) % 26 + 65) } elseif ($c -ge 97 -and $c -le 122) { [char](($c - 97 + 13) % 26 + 97) } else { $m } }
                            $results += @{ guid = $guid; name_encoded = $name; name_decoded = $decoded }
                        }
                    }
                }
            }
            $results
        }
    }

    Collect "bam_dam" {
        $bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
        if (Test-Path $bamPath) {
            $results = @()
            Get-ChildItem $bamPath -ErrorAction SilentlyContinue | ForEach-Object {
                $sid = $_.PSChildName
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                foreach ($name in $props.PSObject.Properties.Name) {
                    if ($name -notlike "PS*" -and $name -ne "Version" -and $name -ne "SequenceNumber") {
                        $results += @{ sid = $sid; executable = $name }
                    }
                }
            }
            $results
        }
    }
}

# ═══════════════════════════════════════════
# Persistence (advanced)
# ═══════════════════════════════════════════

if (-not $Quick) {
    Collect "wmi_subscriptions" {
        $results = @()
        Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | ForEach-Object {
            $results += @{ type = "EventFilter"; name = $_.Name; query = $_.Query; language = $_.QueryLanguage }
        }
        Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
            $results += @{ type = "EventConsumer"; name = $_.Name; class = $_.PSObject.TypeNames[0] }
        }
        Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | ForEach-Object {
            $results += @{ type = "Binding"; filter = $_.Filter; consumer = $_.Consumer }
        }
        $results
    }

    Collect "bits_jobs" {
        Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | ForEach-Object {
            @{
                display_name = $_.DisplayName
                job_state = $_.JobState.ToString()
                owner = $_.OwnerAccount
                creation_time = $_.CreationTime.ToString("o")
                files = ($_.FileList | ForEach-Object { @{ remote = $_.RemoteName; local = $_.LocalName } })
            }
        }
    }

    Collect "recycle_bin" {
        $shell = New-Object -ComObject Shell.Application
        $rb = $shell.NameSpace(0x0A)
        if ($rb) {
            $rb.Items() | ForEach-Object {
                @{
                    name = $_.Name
                    path = $_.Path
                    size = $_.Size
                    modified = $_.ModifyDate
                    type = $_.Type
                }
            }
        }
    }
}

Collect "powershell_history" {
    $histPaths = @(
        "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        "$env:USERPROFILE\.local\share\powershell\PSReadLine\ConsoleHost_history.txt"
    )
    $results = @()
    foreach ($hp in $histPaths) {
        if (Test-Path $hp) {
            $lines = Get-Content $hp -Tail 200 -ErrorAction SilentlyContinue
            $results += @{ path = $hp; line_count = $lines.Count; last_200 = $lines }
        }
    }
    $results
}

# ═══════════════════════════════════════════
# User activity
# ═══════════════════════════════════════════

Collect "local_users" {
    Get-LocalUser | ForEach-Object {
        @{
            name = $_.Name
            enabled = $_.Enabled
            last_logon = $_.LastLogon
            password_last_set = $_.PasswordLastSet
            description = $_.Description
            sid = $_.SID.Value
        }
    }
}

Collect "local_groups" {
    Get-LocalGroup | ForEach-Object {
        $members = Get-LocalGroupMember $_.Name -ErrorAction SilentlyContinue
        @{
            name = $_.Name
            description = $_.Description
            members = $members.Name
        }
    }
}

Collect "logon_sessions" {
    query user 2>&1 | ForEach-Object { $_.ToString() }
}

if (-not $Quick) {
    Collect "browser_history" {
        $results = @()
        # Chrome
        $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
        if (Test-Path $chromePath) {
            $results += @{ browser = "Chrome"; history_path = $chromePath; exists = $true }
        }
        # Edge
        $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
        if (Test-Path $edgePath) {
            $results += @{ browser = "Edge"; history_path = $edgePath; exists = $true }
        }
        # Firefox
        $ffProfiles = "$env:APPDATA\Mozilla\Firefox\Profiles"
        if (Test-Path $ffProfiles) {
            Get-ChildItem $ffProfiles -Filter "places.sqlite" -Recurse | ForEach-Object {
                $results += @{ browser = "Firefox"; history_path = $_.FullName; exists = $true }
            }
        }
        $results
    }

    Collect "recent_files" {
        $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
        if (Test-Path $recentPath) {
            Get-ChildItem $recentPath -Recurse | 
                Sort-Object LastWriteTime -Descending | 
                Select-Object -First 100 | ForEach-Object {
                @{
                    name = $_.Name
                    target = $_.FullName
                    modified = $_.LastWriteTime.ToString("o")
                }
            }
        }
    }
}

# ═══════════════════════════════════════════
# Software & patches
# ═══════════════════════════════════════════

Collect "installed_software" {
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    Get-ItemProperty $paths -ErrorAction SilentlyContinue | 
        Where-Object { $_.DisplayName } | ForEach-Object {
        @{
            name = $_.DisplayName
            version = $_.DisplayVersion
            publisher = $_.Publisher
            install_date = $_.InstallDate
            install_location = $_.InstallLocation
        }
    }
}

if (-not $Quick) {
    Collect "hotfixes" {
        Get-HotFix | ForEach-Object {
            @{
                id = $_.HotFixID
                description = $_.Description
                installed_on = $_.InstalledOn
                installed_by = $_.InstalledBy
            }
        }
    }

    Collect "recently_modified_files" {
        $suspiciousPaths = @(
            "$env:TEMP",
            "$env:APPDATA",
            "C:\Windows\Temp",
            "C:\Users\Public"
        )
        $results = @()
        foreach ($p in $suspiciousPaths) {
            if (Test-Path $p) {
                Get-ChildItem $p -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
                    Sort-Object LastWriteTime -Descending |
                    Select-Object -First 50 | ForEach-Object {
                    $hash = ""
                    if ($_.Length -lt 50MB) {
                        $hash = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                    }
                    $results += @{
                        path = $_.FullName
                        size = $_.Length
                        modified = $_.LastWriteTime.ToString("o")
                        created = $_.CreationTime.ToString("o")
                        sha256 = $hash
                    }
                }
            }
        }
        $results
    }

    Collect "defender_mplogs" {
        # MPLog-*.log files: plain-text Defender troubleshooting logs that
        # carry MUCH richer detail than the Operational EVTX log — process
        # execution evidence, per-file scan results with hashes, real-time
        # detection events, and behavior-monitoring entries that never
        # surface as a Windows Event at all. Requires admin rights to read
        # (same as registry hives) since the folder is locked down.
        #
        # These are NOT parsed here — they ship as raw text lines, same
        # treatment as other text-log sources this collector gathers. The
        # backend's collector.py is responsible for structured parsing
        # (event-type extraction, hash/path correlation) since that keeps
        # parsing logic in one place (Python) instead of duplicating it in
        # PowerShell.
        $mplogDir = "C:\ProgramData\Microsoft\Windows Defender\Support"
        $results = @()
        if (Test-Path $mplogDir) {
            Get-ChildItem $mplogDir -Filter "MPLog-*.log" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 5 |  # most recent logs are highest-value; cap to bound output size
                ForEach-Object {
                $logFile = $_
                try {
                    $lines = Get-Content $logFile.FullName -ErrorAction Stop
                    $results += @{
                        filename = $logFile.Name
                        modified = $logFile.LastWriteTime.ToString("o")
                        size = $logFile.Length
                        line_count = $lines.Count
                        # Cap lines shipped per file — MPLogs can be tens of
                        # MB; the backend parser only needs detection/exec
                        # evidence, not every routine scan-progress line.
                        lines = $lines | Select-Object -First 20000
                    }
                } catch {
                    $results += @{
                        filename = $logFile.Name
                        error = "Could not read (permissions?): $($_.Exception.Message)"
                    }
                }
            }
        } else {
            $results += @{ error = "Defender Support directory not found or inaccessible" }
        }
        $results
    }
}

# ═══════════════════════════════════════════
# Compress & finish
# ═══════════════════════════════════════════

Write-Host ""
Write-Host "  [*] Collection complete" -ForegroundColor Green

$fileCount = (Get-ChildItem $OutputDir -Filter "*.json").Count
$totalSize = (Get-ChildItem $OutputDir | Measure-Object -Property Length -Sum).Sum

Write-Host "  [*] Files: $fileCount artifacts, $([math]::Round($totalSize/1KB))KB total" -ForegroundColor Gray

if (-not $NoZip) {
    $zipPath = "$OutputDir.zip"
    Write-Host "  [*] Compressing to $zipPath..." -ForegroundColor Gray -NoNewline

    try {
        Compress-Archive -Path "$OutputDir\*" -DestinationPath $zipPath -Force
        Write-Host " OK" -ForegroundColor Green

        # Clean up the folder
        Remove-Item $OutputDir -Recurse -Force

        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "  ║  Collection complete!                     ║" -ForegroundColor Green
        Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Output: $zipPath" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Upload this ZIP to the IR Platform dashboard" -ForegroundColor Gray
        Write-Host "  (Collector tab → Upload Collector Results)" -ForegroundColor Gray
        Write-Host ""
    }
    catch {
        Write-Host " FAILED (ZIP stays as folder)" -ForegroundColor Yellow
    }
}
else {
    Write-Host ""
    Write-Host "  Output folder: $OutputDir" -ForegroundColor Cyan
}