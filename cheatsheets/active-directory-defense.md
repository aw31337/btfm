# Active Directory Defense — Command Reference

> BTFM Cheatsheet | Sections 1 & 2 — Identify and Protect  
> Source: Blue Team Field Manual (BTFM) — https://www.amazon.com/dp/B077WF4WYV

---

## AD Inventory & Enumeration (Defense)

```powershell
# Import RSAT AD module
Import-Module ActiveDirectory

# All domain controllers
Get-ADDomainController -Filter *

# All domain admins
Get-ADGroupMember "Domain Admins" -Recursive | Select Name, SamAccountName

# Enterprise admins
Get-ADGroupMember "Enterprise Admins" -Recursive | Select Name, SamAccountName

# Schema admins
Get-ADGroupMember "Schema Admins" -Recursive | Select Name, SamAccountName

# All privileged group members
foreach ($group in @("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Backup Operators")) {
    Write-Host "`n=== $group ===" -ForegroundColor Yellow
    Get-ADGroupMember $group -Recursive | Select Name, SamAccountName
}

# All users with AdminCount=1 (protected objects)
Get-ADUser -Filter {AdminCount -eq 1} | Select Name, SamAccountName, Enabled

# Stale accounts (no logon in 90 days)
$cutoff = (Get-Date).AddDays(-90)
Get-ADUser -Filter {LastLogonDate -lt $cutoff -and Enabled -eq $true} |
    Select Name, SamAccountName, LastLogonDate | Sort LastLogonDate

# Disabled accounts that are still members of privileged groups
Get-ADGroupMember "Domain Admins" | Where-Object {
    (Get-ADUser $_ -Properties Enabled).Enabled -eq $false
}
```

---

## Password Policy

```powershell
# Default domain password policy
Get-ADDefaultDomainPasswordPolicy

# Fine-grained password policies
Get-ADFineGrainedPasswordPolicy -Filter *

# Accounts with password never expires
Get-ADUser -Filter {PasswordNeverExpires -eq $true} | Select Name, SamAccountName

# Accounts with password not required
Get-ADUser -Filter {PasswordNotRequired -eq $true} | Select Name, SamAccountName
```

---

## Group Policy (GPO)

```cmd
# View applied GPOs for computer
gpresult /r

# Detailed GPO report
gpresult /z > gpresult.txt

# HTML report
gpresult /H report.html /F

# Backup all GPOs
```

```powershell
# List all GPOs
Get-GPO -All | Select DisplayName, GpoStatus, ModificationTime | Sort ModificationTime -Desc

# Backup all GPOs
Backup-GPO -All -Path \\<SERVER>\<SHARE>\GPOBackups

# Restore all GPOs
Restore-GPO -All -Domain <DOMAIN> -Path \\<SERVER>\<SHARE>\GPOBackups

# Check GPO links to OUs
Get-GPInheritance -Target "OU=Servers,DC=corp,DC=local"
```

---

## Kerberos Health

```powershell
# Kerberos tickets for current session
klist

# KRBTGT account last password reset (check for Golden Ticket defense)
Get-ADUser krbtgt -Properties PasswordLastSet | Select PasswordLastSet
# Should be reset every 180 days or after any suspected compromise

# Service accounts with SPN (Kerberoastable)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName |
    Select Name, SamAccountName, ServicePrincipalName

# AS-REP Roastable accounts (no pre-auth required)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Select Name, SamAccountName
```

---

## Audit Policy

```cmd
# Check current audit policy
auditpol /get /category:*

# Enable critical categories
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Directory Service Access" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable
auditpol /set /category:"Process Tracking" /success:enable /failure:enable

# Backup audit policy
auditpol /backup /file:C:\auditpolicy.csv

# Restore audit policy
auditpol /restore /file:C:\auditpolicy.csv
```

---

## Key Security Event IDs — AD Focus

| Event ID | Description | Priority |
|---|---|---|
| 4720 | Account created | High |
| 4722 | Account enabled | High |
| 4724 | Password reset attempt | High |
| 4728 | Member added to global security group | High |
| 4732 | Member added to local security group | High |
| 4756 | Member added to universal security group | High |
| 4768 | Kerberos TGT requested | Medium |
| 4769 | Kerberos service ticket requested | Medium |
| 4771 | Kerberos pre-auth failed | High |
| 4776 | DC credential validation | Medium |
| 4648 | Explicit credential logon | High |
| 4672 | Special privileges assigned | High |
| 7045 | New service installed | High |

---

## Lateral Movement Indicators

```powershell
# Recent logon failures
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} |
    Select TimeCreated, @{N='User';E={$_.Properties[5].Value}},
           @{N='Source';E={$_.Properties[19].Value}} |
    Sort TimeCreated -Desc | Select -First 50

# Pass-the-Hash / Pass-the-Ticket indicators (Type 3 logon from unexpected sources)
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} |
    Where-Object { $_.Properties[8].Value -eq 3 } |
    Select TimeCreated, @{N='User';E={$_.Properties[5].Value}},
           @{N='Source';E={$_.Properties[18].Value}} |
    Sort TimeCreated -Desc

# DCSync activity (replication from non-DC)
# Event ID 4662 with "Control Access" right 1131f70a or 9923a32a
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4662} |
    Where-Object { $_.Message -match "1131f70a|9923a32a" }
```

---

## Disable Dangerous Legacy Features

```cmd
# Disable SMBv1
Set-SmbServerConfiguration -EnableSMB1Protocol $false

# Disable LLMNR via GPO (PowerShell)
# Computer Config > Windows Settings > Security Settings > Local Policies > Security Options
# Turn off multicast name resolution

# Disable WPAD
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" /v WpadOverride /t REG_DWORD /d 1

# Restrict anonymous enumeration
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1
```

---

*From the Blue Team Field Manual (BTFM) — https://www.amazon.com/dp/B077WF4WYV*
