# Patching Quick Reference — Windows & Linux

> BTFM Cheatsheet | Section 5 — Recover  
> Source: Blue Team Field Manual (BTFM) — https://www.amazon.com/dp/B077WF4WYV

---

## Windows Patching

### Check Patch Status

```cmd
# All installed hotfixes
wmic qfe list brief

# List KBs sorted by install date
wmic qfe get HotFixID,InstalledOn,Description /format:csv | sort

# Specific KB check
wmic qfe list | findstr "KB<NUMBER>"
```

```powershell
# Rich patch list
Get-WmiObject Win32_QuickFixEngineering |
    Select HotFixID, Description, InstalledOn |
    Sort InstalledOn -Descending

# Check for a specific KB
Get-HotFix -Id KB4571756
```

### Install Updates

```cmd
# Single hotfix (Windows 7+)
wusa.exe C:\<PATH>\patch.msu

# Trigger Windows Update check
wuauclt.exe /detectnow /updatenow

# Batch hotfix install script
@echo off
setlocal
set PATCH_DIR=E:\hotfix
%PATCH_DIR%\KB123456_w2k_sp4_x86.exe /Z /M
%PATCH_DIR%\KB123321_w2k_sp4_x86.exe /Z /M
```

```powershell
# Install Windows Update module (PSWindowsUpdate)
Install-Module PSWindowsUpdate -Force

# List available updates
Get-WindowsUpdate

# Install all updates
Install-WindowsUpdate -AcceptAll -AutoReboot

# Install specific update by KB
Install-WindowsUpdate -KBArticleID KB4571756 -AcceptAll
```

### WSUS / SCCM

```cmd
# Force WSUS sync
wuauclt /reportnow /detectnow

# Check WSUS assignment
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v WUServer
```

---

## Linux Patching

### Ubuntu / Debian

```bash
# Update package list
apt-get update

# Upgrade installed packages (no version bumps)
apt-get upgrade

# Full upgrade (may change package versions)
apt-get dist-upgrade

# Install security updates only
apt-get install unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades

# Install specific package
apt-get install <PACKAGE>

# Check available security updates
apt list --upgradable 2>/dev/null | grep -i security

# Simulate upgrade (no change)
apt-get --simulate upgrade
```

### RHEL / CentOS 6 & 7

```bash
# Check for updates
yum check-update

# Apply all updates
yum update

# Security updates only
yum update --security

# Apply specific advisory
yum update --advisory=RHSA-2021:12345

# Install specific package
yum install <PACKAGE>

# List installed version
yum list installed <PACKAGE>

# RHEL 2.1/3/4 legacy
up2date
up2date-nox --update
up2date -u <PACKAGE>
```

### RHEL / CentOS 8+ / Fedora

```bash
# DNF (replaces yum)
dnf check-update
dnf update
dnf update --security
dnf update --advisory=RHSA-2021:12345
dnf install <PACKAGE>
```

### Kali Linux

```bash
# Standard update
apt-get update && apt-get upgrade

# Full upgrade
apt-get update && apt-get full-upgrade
```

---

## Backup & Rollback (Windows)

```cmd
# Backup GPO audit policy
auditpol /backup /file:C:\auditpolicy.csv

# Restore audit policy
auditpol /restore /file:C:\auditpolicy.csv

# Start Volume Shadow Service
net start VSS

# List shadow copies
vssadmin List Shadows
vssadmin List ShadowStorage

# Browse a shadow copy
mklink /d C:\vss \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

# Revert to shadow copy (Windows Server / Win 8+)
vssadmin revert shadow /shadow={<SHADOW_COPY_ID>} /ForceDismount
```

```powershell
# Backup all GPOs
Backup-GPO -All -Path \\<SERVER>\<SHARE>\GPOBackups

# Restore all GPOs
Restore-GPO -All -Domain <DOMAIN> -Path \\<SERVER>\<SHARE>\GPOBackups
```

---

## Backup & Rollback (Linux)

```bash
# Snapshot with rsync before patching
rsync -avz --delete /etc/ /backup/etc_$(date +%Y%m%d)/

# Hold a package version (apt)
apt-mark hold <PACKAGE>
apt-mark unhold <PACKAGE>

# Lock a package version (yum)
yum versionlock add <PACKAGE>
yum versionlock delete <PACKAGE>

# Roll back a yum transaction
yum history list
yum history info <ID>
yum history undo <ID>

# Roll back a dnf transaction
dnf history list
dnf history undo <ID>
```

---

## Patch Verification Checklist

- [ ] Patch list from vendor advisory reviewed
- [ ] Test environment patched first
- [ ] System snapshot / VSS taken before patching
- [ ] Maintenance window communicated
- [ ] Patch installed and KB confirmed in patch list
- [ ] Services restarted if required
- [ ] Functionality tested (golden path)
- [ ] Patch status confirmed in SCCM / WSUS / vulnerability scanner
- [ ] Rollback procedure documented

---

*From the Blue Team Field Manual (BTFM) — https://www.amazon.com/dp/B077WF4WYV*
