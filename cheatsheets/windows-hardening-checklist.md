# Windows Hardening Checklist
*Section 2 — PROTECT | BTFM v2*

Quick-reference hardening steps for Windows systems during incident response or pre-engagement setup.
Assumes Windows 10/11 or Windows Server 2019+.

---

## Account Hardening

```
net user Administrator /active:no          # Disable built-in Administrator
net user Guest /active:no                  # Disable Guest account
```

- Rename the Administrator account via Group Policy or `secpol.msc`
- Compare active user list against known-good roster
- Check user creation dates for anomalies:
```powershell
Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet | Sort-Object LastLogon -Descending
```

Set account lockout policy (3–5 attempts, lockout forever until admin release):
```
net accounts /lockoutthreshold:3 /lockoutduration:0 /lockoutwindow:30
```

Minimum password length 15 characters:
```
net accounts /minpwlen:15
```

---

## Firewall

Enable Windows Firewall for all profiles:
```
netsh advfirewall set allprofiles state on
```

Enable connection logging:
```
netsh advfirewall set allprofile logging allowedconnections enable
netsh advfirewall set allprofile logging droppedconnections enable
```

Check current firewall rules:
```
netsh advfirewall firewall show rule name=all
```

---

## Services

List running services and their executables:
```
sc query type= all state= running
wmic service where "state='running'" get name,pathname,startmode
```

Stop a suspicious service:
```
sc stop <SERVICE_NAME>
sc config <SERVICE_NAME> start= disabled
```

Check for services running under admin/system credentials:
```powershell
Get-WmiObject Win32_Service | Where-Object {$_.StartName -match "Admin|System"} | Select-Object Name,StartName,PathName
```

---

## Shares

List all shares and remove unauthorized ones:
```
net share
net share <SHARE_NAME> /delete
```

---

## NTP — Synchronize Time (Reliable Logs)

Enable and start Windows Time service:
```
net start w32time
w32tm /resync /force
```

---

## Patching

Check for missing updates (PowerShell):
```powershell
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
```

---

## Remote Services — Disable If Not Required

Disable Remote Desktop:
```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
```

Disable Remote Registry:
```
sc config RemoteRegistry start= disabled
sc stop RemoteRegistry
```

---

## Establish a Baseline

Capture current state immediately on engagement:
```
netstat -abfo > baseline-netstat.txt
net user > baseline-users.txt
net share > baseline-shares.txt
tasklist /v > baseline-processes.txt
wmic startup list full > baseline-startup.txt
schtasks /query /fo LIST /v > baseline-tasks.txt
```
Ref. https://github.com/cottinghamd/HardeningAuditor
