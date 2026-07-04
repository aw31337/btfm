# windows-triage.ps1 — Full Windows incident response triage collection
# BTFM Section 4 — Respond | https://www.amazon.com/dp/B077WF4WYV
#
# Run as Administrator.
# Usage: .\windows-triage.ps1 [-OutputDir <path>] [-CaseID <id>]
#
# Collects: system info, network state, processes, services, startup,
#           scheduled tasks, users, patches, registry autoruns, security events.

[CmdletBinding()]
param(
    [string]$OutputDir = "C:\IR_Triage_$(hostname)_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [string]$CaseID = "CASE-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
)

$ErrorActionPreference = "SilentlyContinue"

# ── Setup ─────────────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$LogFile = Join-Path $OutputDir "triage.log"

function Log($msg) {
    $ts = Get-Date -Format "HH:mm:ss"
    "[$ts] $msg" | Tee-Object -FilePath $LogFile -Append
}

Log "Windows Triage Started — Case ID: $CaseID"
Log "Output: $OutputDir"
Log "Host: $(hostname)"
Log "Analyst: $env:USERNAME"

# ── System Information ─────────────────────────────────────────────────────────
Log "Collecting system information"
@{
    CaptureTime   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    Hostname      = $env:COMPUTERNAME
    Domain        = (Get-WmiObject Win32_ComputerSystem).Domain
    OS            = (Get-WmiObject Win32_OperatingSystem).Caption
    OSVersion     = (Get-WmiObject Win32_OperatingSystem).Version
    InstallDate   = (Get-WmiObject Win32_OperatingSystem).InstallDate
    LastBoot      = (Get-WmiObject Win32_OperatingSystem).LastBootUpTime
    Architecture  = $env:PROCESSOR_ARCHITECTURE
    TotalRAM_GB   = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
    BIOS          = (Get-WmiObject Win32_BIOS).SMBIOSBIOSVersion
    SerialNumber  = (Get-WmiObject Win32_BIOS).SerialNumber
} | Format-List | Out-File "$OutputDir\system_info.txt"

systeminfo | Out-File "$OutputDir\systeminfo_full.txt"

# ── Network State ─────────────────────────────────────────────────────────────
Log "Collecting network state (volatile)"
netstat -naob | Out-File "$OutputDir\netstat.txt"
netstat -nr | Out-File "$OutputDir\routing_table.txt"
arp -a | Out-File "$OutputDir\arp_cache.txt"
ipconfig /all | Out-File "$OutputDir\ipconfig.txt"
ipconfig /displaydns | Out-File "$OutputDir\dns_cache.txt"
netsh winhttp show proxy | Out-File "$OutputDir\proxy.txt"
type "$env:SYSTEMROOT\system32\drivers\etc\hosts" | Out-File "$OutputDir\hosts_file.txt"

Get-NetTCPConnection |
    Select LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
    Sort State | Out-File "$OutputDir\tcp_connections.txt"

# ── Processes ─────────────────────────────────────────────────────────────────
Log "Collecting process list"
Get-Process |
    Select Id, Name, Path, Company, StartTime, CPU, WorkingSet |
    Sort StartTime -Descending |
    Out-File "$OutputDir\processes.txt"

# Processes with no path (potential injection or deleted binaries)
Get-Process | Where-Object { [string]::IsNullOrEmpty($_.Path) } |
    Select Id, Name, CPU |
    Out-File "$OutputDir\processes_no_path.txt"

# ── Services ──────────────────────────────────────────────────────────────────
Log "Collecting services"
Get-Service | Where-Object { $_.Status -eq "Running" } |
    Select Name, DisplayName, Status, StartType |
    Sort Name |
    Out-File "$OutputDir\services_running.txt"

Get-WmiObject Win32_Service |
    Select Name, DisplayName, State, PathName, StartName |
    Sort Name |
    Out-File "$OutputDir\services_all.txt"

# ── Scheduled Tasks ───────────────────────────────────────────────────────────
Log "Collecting scheduled tasks"
Get-ScheduledTask |
    Where-Object { $_.State -ne "Disabled" } |
    Select TaskName, TaskPath, State, @{N='Run';E={($_.Actions | Select -First 1).Execute}} |
    Sort TaskPath |
    Out-File "$OutputDir\scheduled_tasks.txt"

schtasks /query /fo CSV /v | Out-File "$OutputDir\schtasks_full.csv"

# ── Startup / Autoruns ────────────────────────────────────────────────────────
Log "Collecting autorun locations"
$autorunKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)

$autoruns = foreach ($key in $autorunKeys) {
    if (Test-Path $key) {
        $props = Get-ItemProperty $key
        foreach ($name in ($props.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }).Name) {
            [PSCustomObject]@{ Key = $key; Name = $name; Value = $props.$name }
        }
    }
}
$autoruns | Out-File "$OutputDir\autoruns_registry.txt"

Get-WmiObject Win32_StartupCommand |
    Select Name, Command, Location, User |
    Out-File "$OutputDir\autoruns_wmi.txt"

# ── Users & Groups ────────────────────────────────────────────────────────────
Log "Collecting user accounts"
Get-LocalUser |
    Select Name, Enabled, LastLogon, PasswordExpires, PasswordNeverExpires |
    Sort Name |
    Out-File "$OutputDir\local_users.txt"

Get-LocalGroupMember "Administrators" |
    Select Name, ObjectClass, PrincipalSource |
    Out-File "$OutputDir\local_admins.txt"

net users | Out-File "$OutputDir\net_users.txt"
net localgroup administrators | Out-File "$OutputDir\net_admins.txt"

# ── Patches / Updates ─────────────────────────────────────────────────────────
Log "Collecting patch history"
Get-WmiObject Win32_QuickFixEngineering |
    Select HotFixID, Description, InstalledOn |
    Sort InstalledOn -Descending |
    Out-File "$OutputDir\patches.txt"

# ── Security Event Logs ───────────────────────────────────────────────────────
Log "Collecting security events"
$securityIds = @(
    4624,  # Successful logon
    4625,  # Failed logon
    4634,  # Logoff
    4648,  # Explicit credential logon
    4672,  # Special privileges
    4720,  # Account created
    4728,  # Added to global security group
    4732,  # Added to local security group
    4768,  # Kerberos TGT
    4769,  # Kerberos service ticket
    7045   # New service installed
)

Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = $securityIds
    StartTime = (Get-Date).AddDays(-7)
} | Select TimeCreated, Id, @{N='Message';E={$_.Message.Substring(0,[Math]::Min(200,$_.Message.Length))}} |
    Sort TimeCreated -Descending |
    Out-File "$OutputDir\security_events.txt"

# Failed logons summary
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-1)} |
    Group-Object { $_.Properties[5].Value } |
    Select Name, Count |
    Sort Count -Descending |
    Out-File "$OutputDir\failed_logons_summary.txt"

# ── Hash All Output ────────────────────────────────────────────────────────────
Log "Hashing output files"
Get-ChildItem $OutputDir -File | Where-Object { $_.Name -ne "hashes.txt" } |
    ForEach-Object {
        $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        "$hash  $($_.Name)"
    } | Out-File "$OutputDir\hashes.txt"

Log "Triage complete"
Write-Host "`nOutput directory: $OutputDir" -ForegroundColor Green
Write-Host "File count: $((Get-ChildItem $OutputDir -File).Count)" -ForegroundColor Green
