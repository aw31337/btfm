# Script: event-log-hunt.ps1
# Purpose: Hunt Windows event logs for common attack indicators
# Usage: .\event-log-hunt.ps1 [-Hours 24] [-Export]
# Requirements: PowerShell 5.1+, local admin or event log read rights
# BTFM Reference: Section 4 — Windows Log Analysis

param(
    [int]$Hours = 24,
    [switch]$Export
)

$Since = (Get-Date).AddHours(-$Hours)
$Results = @()

Write-Host "[*] Hunting event logs from the last $Hours hours..." -ForegroundColor Cyan

# --- Account Events ---
$AccountEvents = @{
    4624 = "Successful Logon"
    4625 = "Failed Logon"
    4648 = "Logon with Explicit Credentials"
    4720 = "User Account Created"
    4722 = "User Account Enabled"
    4724 = "Password Reset Attempt"
    4728 = "User Added to Security Group"
    4732 = "User Added to Local Group"
    4756 = "User Added to Universal Group"
    4768 = "Kerberos TGT Request"
    4769 = "Kerberos Service Ticket Request"
    4771 = "Kerberos Pre-Auth Failed"
    4776 = "NTLM Auth Attempt"
}

# --- Process/Execution Events (requires Sysmon or audit policy) ---
$ExecEvents = @{
    4688 = "Process Created"
    4697 = "Service Installed"
    7045 = "New Service Installed (System log)"
}

# --- Lateral Movement Indicators ---
$LateralEvents = @{
    4648 = "Explicit Credentials Used"
    4778 = "RDP Session Reconnected"
    4779 = "RDP Session Disconnected"
    5140 = "Network Share Accessed"
    5145 = "Network Share Object Check"
}

function Get-Events {
    param([string]$Log, [hashtable]$EventIds, [string]$Category)
    foreach ($Id in $EventIds.Keys) {
        try {
            $Events = Get-WinEvent -FilterHashtable @{
                LogName   = $Log
                Id        = $Id
                StartTime = $Since
            } -ErrorAction SilentlyContinue
            if ($Events) {
                foreach ($Evt in $Events) {
                    $Results += [PSCustomObject]@{
                        Category    = $Category
                        EventID     = $Id
                        Description = $EventIds[$Id]
                        TimeCreated = $Evt.TimeCreated
                        Message     = $Evt.Message -replace '\s+', ' ' | Select-Object -First 1
                    }
                }
            }
        } catch {}
    }
}

Get-Events -Log "Security" -EventIds $AccountEvents  -Category "Account"
Get-Events -Log "Security" -EventIds $ExecEvents     -Category "Execution"
Get-Events -Log "Security" -EventIds $LateralEvents  -Category "Lateral"

# --- Failed logon summary (brute force indicator) ---
$FailedLogons = $Results | Where-Object { $_.EventID -eq 4625 }
if ($FailedLogons.Count -gt 10) {
    Write-Host "[!] $($FailedLogons.Count) failed logons in $Hours hours — possible brute force" -ForegroundColor Red
}

# --- Display ---
$Results | Sort-Object TimeCreated -Descending | Format-Table Category, EventID, Description, TimeCreated -AutoSize

Write-Host "`n[+] Total events found: $($Results.Count)"

if ($Export) {
    $OutFile = ".\event-hunt-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    $Results | Export-Csv -Path $OutFile -NoTypeInformation
    Write-Host "[+] Exported to $OutFile"
}
