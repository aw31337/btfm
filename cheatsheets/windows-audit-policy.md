# Windows Audit Policy (auditpol)
*Section 1 — IDENTIFY | BTFM v2*

Enable granular audit logging via `auditpol`. Run as Administrator on Windows 10/11 and Server 2019+.

---

## View Current Audit Policy

```
auditpol /get /category:*
```

---

## Export / Backup Current Policy

```
auditpol /backup /file:C:udit_backup.csv
```

Restore from backup:
```
auditpol /restore /file:C:udit_backup.csv
```

---

## Enable by Subcategory (Object Access)

```
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable
auditpol /set /subcategory:"SAM" /success:enable /failure:enable
auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
```

## Enable by Subcategory (Privilege Use)

```
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Other Privilege Use Events" /success:enable /failure:enable
```

## Enable by Subcategory (Process Tracking)

```
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
auditpol /set /subcategory:"DPAPI Activity" /success:enable /failure:enable
auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable
```

## Enable by Subcategory (Policy Change)

```
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Other Policy Change Events" /success:enable /failure:enable
```

## Enable by Subcategory (Account Management)

```
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable
```

## Enable by Subcategory (Directory Service)

```
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Replication" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed Directory Service Replication" /success:enable /failure:enable
```

## Enable by Subcategory (Account Logon / Kerberos)

```
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable
auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable
```

---

## wevtutil — Export & Query Event Logs

Export Application log to file:
```
wevtutil export-log Application /r:C:\Windows\Temp\ /ow:True
```

Query System log, last 20 events, plain text:
```
WEVTUtil query-events System /count:20 /rd:true /format:text > eventlog.txt
```

Query for specific Event ID (e.g. 1074 — system shutdown):
```
WEVTUtil query-events System /count:20 /rd:true /format:text /q:"Event[System[(EventID=1074)]]" > eventlog.csv
```

Export ALL logs (PowerShell loop):
```powershell
wevtutil el | foreach-object { wevtutil export-log "$_" "$_.evtx" }
```

Search log files for an IP pattern:
```powershell
Select-String -Path C:\Logs\*.log -Pattern '192.168.*'
```

Check Windows Firewall log:
```powershell
Get-Content C:\Windows\System32\LogFiles\Firewall\pfirewall.log
```

Enable firewall connection logging:
```
netsh advfirewall set allprofile logging allowedconnections enable
```
