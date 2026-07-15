# Active Directory Hunting
*Section 3 — DETECT | BTFM v2*

Commands for hunting threats and enumerating suspicious activity in Active Directory environments.
Requires RSAT / ActiveDirectory PowerShell module or domain-joined system.

---

## Find Privileged Accounts (AdminCount=1)

Enumerate all users and groups that have ever held elevated privileges:
```powershell
Import-Module ActiveDirectory
Get-ADObject -LDAPFilter "(&(admincount=1)(|(objectcategory=person)(objectcategory=group)))" -Properties MemberOf,Created,Modified,AdminCount | Select-Object Name,ObjectClass,Created,Modified,AdminCount | Sort-Object ObjectClass,Name
```

---

## User Account Enumeration

List all domain users with last logon:
```
net user /domain
```

Last logon for a specific user:
```
net user <USERNAME> /domain | findstr /C:"Last logon"
```

Last logon for local administrator:
```
net user administrator | findstr /B /C:"Last logon"
```

---

## Kerberos Audit Policy (auditpol)

Enable Kerberos ticket and authentication auditing:
```
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
```

---

## Baseline Snapshot (Run Immediately on Engagement)

```
netstat -abfo > baseline-netstat.txt
net user > baseline-users.txt
net share > baseline-shares.txt
net computer > baseline-computers.txt
tasklist /v > baseline-processes.txt
```

---

## Process Investigation

Get command line for a running process (PowerShell):
```powershell
Get-WmiObject Win32_Process -Filter "name = '<PROCESS>.exe'" | Select-Object ProcessId,Name,CommandLine
```

List all processes with their paths:
```powershell
Get-Process | Select-Object Id,Name,Path | Sort-Object Name
```

---

## Detect Lateral Movement — Open File Shares

List open network sessions:
```
net file
```

List SMB sessions on local system:
```
net session
```

---

## Check for Unauthorized Shares

```
net share
```

---

## IPSec Policy (Filter Suspicious Traffic)

Create a policy to monitor/block a specific IP or port:
```
netsh ipsec static add filter filterlist=MyIPsecFilter srcaddr=Any dstaddr=Any protocol=ANY
netsh ipsec static add filteraction name=MyIPsecAction action=negotiate
netsh ipsec static add policy name=MyIPsecPolicy assign=yes
netsh ipsec static add rule name=MyIPsecRule policy=MyIPsecPolicy filterlist=MyIPsecFilter filteraction=MyIPsecAction conntype=all activate=yes psk=<PRESHARED_KEY>
```

---

## Certificate Inspection (Detect Rogue Certs)

Examine a certificate file:
```bash
openssl x509 -text -in cert.pem
```
