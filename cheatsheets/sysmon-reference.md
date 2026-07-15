# Sysmon Reference
*Section 2 — PROTECT | BTFM v2*

Sysmon (System Monitor) provides detailed Windows event logging beyond native audit policy.
Download: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

---

## Install

Install with MD5 hashing and network connection monitoring (32-bit):
```
sysmon.exe -i -accepteula -h md5 -n
```

Install (64-bit):
```
sysmon64.exe -i -accepteula -h md5 -n
```

Install with a config file (recommended — use olafhartong/sysmon-modular):
```
sysmon64.exe -i -accepteula sysmonconfig.xml
```
Ref. https://github.com/olafhartong/sysmon-modular

---

## Update Config

```
sysmon64.exe -c sysmonconfig.xml
```

---

## Uninstall

```
sysmon64.exe -u
```

---

## Query Sysmon Logs (PowerShell)

Read Sysmon operational log from file:
```powershell
Get-WinEvent -Path C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | Format-List *
```

Filter for network connections (Event ID 3):
```powershell
Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational"; id=3} | Select-Object -First 10 | Format-List *
```

Read from remote system:
```powershell
Get-WinEvent -ComputerName <TARGET_IP> -Credential <DOMAIN>\<USER> -Path C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | Where-Object {$_.EventID -lt 3} | Format-List *
```

Most recent event from live log:
```powershell
Get-EventLog -log "Microsoft-Windows-Sysmon/Operational" -newest 1 | Format-List -Property *
```

---

## Key Sysmon Event IDs

| ID | Event |
|----|-------|
| 1  | Process creation |
| 2  | File creation time changed |
| 3  | Network connection |
| 4  | Sysmon service state changed |
| 5  | Process terminated |
| 6  | Driver loaded |
| 7  | Image loaded (DLL) |
| 8  | CreateRemoteThread |
| 9  | RawAccessRead |
| 10 | ProcessAccess (e.g. LSASS access) |
| 11 | FileCreate |
| 12 | Registry object added/deleted |
| 13 | Registry value set |
| 15 | FileCreateStreamHash (ADS) |
| 17 | PipeEvent — created |
| 18 | PipeEvent — connected |
| 22 | DNS query |
| 23 | File delete archived |
| 25 | Process tampering |

---

## Sysmon Log Path

```
C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx
```
