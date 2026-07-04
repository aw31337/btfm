# Windows Live Triage — Command Reference

> BTFM Cheatsheet | Section 4 — Respond  
> Source: Blue Team Field Manual (BTFM) — https://www.amazon.com/dp/B077WF4WYV

Run from an elevated CMD or PowerShell prompt. For incident response — capture volatile state before anything else modifies it.

---

## System Information

```cmd
echo %DATE% %TIME%
hostname
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
wmic csproduct get name
wmic bios get serialnumber
wmic computersystem list brief
wmic product get name,version
echo %PATH%
psinfo -accepteula -s -h -d
```

---

## User Information

```cmd
whoami
net users
net localgroup administrators
net group administrators
wmic rdtoggle list
wmic useraccount list
wmic group list
wmic netlogin get name,lastlogon,badpasswordcount
wmic netclient list brief
doskey /history > history.txt
```

```powershell
# Logged-in users
Get-LocalUser | Select Name, Enabled, LastLogon
Get-LocalGroupMember Administrators
query session
```

---

## Network Information

```cmd
netstat -e
netstat -naob
netstat -nr
netstat -vb
nbtstat -S
route print
arp -a
ipconfig /displaydns
ipconfig /allcompartments /all
netsh winhttp show proxy
netsh wlan show interfaces
netsh wlan show all
type %SYSTEMROOT%\system32\drivers\etc\hosts
wmic nicconfig get descriptions,IPaddress,MACaddress
wmic netuse get name,username,connectiontype,localname
```

---

## Process & Service Information

```cmd
at
tasklist
tasklist /svc
tasklist /svc /fi "imagename eq svchost.exe"
tasklist /svc /fi "pid eq <PID>"
schtasks
net start
sc query
wmic service list brief | findstr "Running"
wmic service list config
wmic process list brief
wmic process list status
wmic process list memory
wmic job list brief
```

```powershell
Get-Service | Where-Object { $_.Status -eq "running" }
Get-Process | Select-Object Id, Name, Path, StartTime | Sort StartTime -Desc
Get-Process | select modules | Foreach-Object { $_.modules }
Get-ScheduledTask | Where-Object State -ne Disabled | Select TaskName, TaskPath
Get-NetTCPConnection | Where-Object State -eq Established
Get-NetTCPConnection | Where-Object State -eq Listen | Select LocalPort, OwningProcess
```

---

## Autorun / Startup

```cmd
wmic startup list full
wmic ntdomain list brief
dir "%SystemDrive%\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
dir "%SystemDrive%\Documents and Settings\All Users\Start Menu\Programs\Startup"
dir "%userprofile%\Start Menu\Programs\Startup"
dir "C:\Windows\Start Menu\Programs\startup"
dir "C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
```

```powershell
# All autorun locations (Sysinternals)
# autorunsc.exe -accepteula -a * -s -c -h > autoruns.csv
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

---

## Policy & Patch Information

```cmd
set
gpresult /r
gpresult /z > gpresult.txt
gpresult /H report.html /F
wmic qfe
```

---

## File System Activity

```powershell
# Recently modified files (last 24 hours)
Get-ChildItem C:\Users -Recurse -Force |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) } |
  Sort LastWriteTime -Desc | Select FullName, LastWriteTime | Select -First 50

# Temp directories
dir %TEMP%
dir C:\Windows\Temp
```

---

## Registry — Key Forensic Locations

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SYSTEM\CurrentControlSet\Services"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
```

---

## Memory Capture (Windows)

```powershell
# WinPmem (open source)
winpmem.exe memory.raw

# DumpIt
DumpIt.exe /O memory.dmp /T RAW

# Hash immediately after capture
Get-FileHash memory.raw -Algorithm SHA256
Get-FileHash memory.raw -Algorithm MD5
```

---

## Log Collection

```cmd
wevtutil qe Security /f:text /rd:true /c:500 > security_events.txt
wevtutil qe System /f:text /rd:true /c:500 > system_events.txt
wevtutil qe Application /f:text /rd:true /c:200 > application_events.txt
```

```powershell
# Export specific event IDs
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4648,4768,4769} |
  Select TimeCreated, Id, Message | Export-Csv auth_events.csv

# All failed logons
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} |
  Select TimeCreated, @{N='Account';E={$_.Properties[5].Value}}, Message |
  Sort TimeCreated -Desc
```

---

## Quick Hash of Suspicious File

```powershell
Get-FileHash C:\path\to\suspicious.exe -Algorithm SHA256
Get-FileHash C:\path\to\suspicious.exe -Algorithm MD5
```

---

## Triage Collection Script (one-liner)

```cmd
FOR /F "tokens=2 delims==" %i IN ('wmic computersystem get name /value') DO SET HOST=%i
mkdir %HOST%_triage
systeminfo > %HOST%_triage\systeminfo.txt
netstat -naob > %HOST%_triage\netstat.txt
tasklist /svc > %HOST%_triage\tasklist.txt
wmic process list full > %HOST%_triage\processes.txt
wmic service list brief > %HOST%_triage\services.txt
wmic startup list full > %HOST%_triage\startup.txt
wmic qfe > %HOST%_triage\patches.txt
dir C:\Users > %HOST%_triage\users.txt
```

---

*From the Blue Team Field Manual (BTFM) — https://www.amazon.com/dp/B077WF4WYV*
